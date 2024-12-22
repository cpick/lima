package usernet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	launchd "github.com/bored-engineer/go-launchd"
	gvproxyclient "github.com/containers/gvisor-tap-vsock/pkg/client"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/lima-vm/lima/pkg/driver"
	"github.com/lima-vm/lima/pkg/httpclientutil"
	"github.com/lima-vm/lima/pkg/limayaml"
	"github.com/lima-vm/lima/pkg/networks/usernet/dnshosts"
	"github.com/sirupsen/logrus"
)

type Client struct {
	Directory string

	client      *http.Client
	delegate    *gvproxyclient.Client
	base        string
	subnet      net.IP
	unExposeSSH *types.UnexposeRequest
}

func (c *Client) ConfigureDriver(ctx context.Context, driver *driver.BaseDriver) error {
	macAddress := limayaml.MACAddress(driver.Instance.Dir)
	ipAddress, err := c.ResolveIPAddress(ctx, macAddress)
	if err != nil {
		return err
	}
	if *driver.Instance.Config.SSH.LaunchdSocketName != "" {
		err = c.forwardLaunchdToSSH(ipAddress, *driver.Instance.Config.SSH.LaunchdSocketName)
		if err != nil {
			return err
		}
	} else {
		err = c.ResolveAndForwardSSH(ipAddress, driver.SSHLocalPort)
		if err != nil {
			return err
		}
	}
	hosts := driver.Instance.Config.HostResolver.Hosts
	hosts[fmt.Sprintf("%s.internal", driver.Instance.Hostname)] = ipAddress
	err = c.AddDNSHosts(hosts)
	return err
}

func (c *Client) UnExposeSSH() error {
	if c.unExposeSSH == nil {
		return errors.New("SSH not exposed")
	}

	if err := c.delegate.Unexpose(c.unExposeSSH); err != nil {
		return err
	}
	c.unExposeSSH = nil

	return nil
}

func (c *Client) AddDNSHosts(hosts map[string]string) error {
	hosts["host.lima.internal"] = GatewayIP(c.subnet)
	zones := dnshosts.ExtractZones(hosts)
	for _, zone := range zones {
		err := c.delegate.AddDNS(&zone)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) ResolveAndForwardSSH(ipAddr string, sshPort int) error {
	if c.unExposeSSH != nil {
		return errors.New("SSH already exposed")
	}

	req := &types.ExposeRequest{
		Local:    fmt.Sprintf("127.0.0.1:%d", sshPort),
		Remote:   fmt.Sprintf("%s:22", ipAddr),
		Protocol: "tcp",
	}

	err := c.delegate.Expose(req)
	if err != nil {
		return err
	}

	c.unExposeSSH = &types.UnexposeRequest{
		Local:    req.Local,
		Protocol: req.Protocol,
	}
	return nil
}

func (c *Client) forwardListenerToSSH(remote string, l net.Listener) error {
	defer l.Close()

	if c.unExposeSSH != nil {
		return errors.New("SSH already exposed")
	}

	existingFwds, err := c.delegate.List()
	if err != nil {
		return fmt.Errorf("failed to get list existing forwards: %w", err)
	}

	tl, ok := l.(*net.TCPListener)
	if !ok {
		return errors.New("not TCP listener")
	}

	rc, err := tl.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw connection: %w", err)
	}

	var innerErr error
	if err := rc.Control(func(fd uintptr) {
		if fd > math.MaxInt {
			innerErr = fmt.Errorf("invalid fd: %v", fd)
			return
		}
		local := strconv.Itoa(int(fd))

		if err := c.delegate.Expose(&types.ExposeRequest{
			Local:    local,
			Remote:   remote,
			Protocol: types.TCPFD,
		}); err != nil {
			innerErr = fmt.Errorf("exposing fd: %v failed: %w", fd, err)
			return
		}
	}); err != nil {
		return fmt.Errorf("failed to control raw connection: %w", err)
	}
	if innerErr != nil {
		return innerErr
	}

	currentFwds, err := c.delegate.List()
	if err != nil {
		return fmt.Errorf("failed to get list current forwards: %w", err)
	}

	// save unexpose request based on new forward
	var newFwd *types.ExposeRequest
	for _, fwd := range currentFwds {
		if len(existingFwds) == 0 || fwd != existingFwds[0] {
			if newFwd != nil {
				return fmt.Errorf("found multiple new forwards: %v and %v", newFwd, fwd)
			}
			newFwd = &fwd
			continue // don't break to ensure there's only one new forward
		}
		existingFwds = existingFwds[1:]
	}
	if newFwd == nil {
		return errors.New("failed to find new forward")
	}
	c.unExposeSSH = &types.UnexposeRequest{
		Local:    newFwd.Local,
		Protocol: newFwd.Protocol,
	}
	return nil
}

// wait for VM to start accepting connections on its SSH port
func (c *Client) awaitSSHViaForward(remote string) error {
	// overall timeout/deadline
	t := 60 * time.Second
	dlt := time.After(t)
	dl := time.Now().Add(t)

	// test listener
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("test socket failed to listen: %w", err)
	}
	addr := l.Addr()

	if err := c.forwardListenerToSSH(remote, l); err != nil {
		return fmt.Errorf("failed to forward test socket to SSH: %w", err)
	}
	defer c.UnExposeSSH()

	// await SSH
	d := net.Dialer{
		Deadline: dl,
	}
	rlt := time.Tick(time.Second)
	for {
		conn, err := d.Dial(addr.Network(), addr.String())
		if err != nil {
			return fmt.Errorf("failed to set dial: %w", err)
		}
		defer conn.Close()

		if err := conn.SetDeadline(dl); err != nil {
			return fmt.Errorf("failed to set connection deadline: %w", err)
		}

		// test a read
		if _, err := conn.Read([]byte{0}); err == nil {
			return nil
		} else if !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to read from connection: %w", err)
		}

		// rate limit
		select {
		case <-dlt:
			return fmt.Errorf("failed while rate limited: %w", os.ErrDeadlineExceeded)
		case <-rlt: // carry on
		}
	}
}

func (c *Client) forwardLaunchdToSSH(ipAddr string, sshLaunchdSocketName string) error {
	remote := net.JoinHostPort(ipAddr, "22")

	// wait for SSH in VM to ensure that the first launchd connection succeeds
	if err := c.awaitSSHViaForward(remote); err != nil {
		logrus.Warnf("failed to await SSH via forward; first connection may fail, but continuing anyway: %w", err)
		// carry on
	}

	// forward the launchd socket
	l, err := launchd.Activate(sshLaunchdSocketName)
	if err != nil {
		return fmt.Errorf("launchd socket %q failed to activate: %w", sshLaunchdSocketName, err)
	}
	if err := c.forwardListenerToSSH(remote, l); err != nil {
		return fmt.Errorf("forwarding launchd socket %q to SSH failed: %w", sshLaunchdSocketName, err)
	}

	return nil
}

func (c *Client) ResolveIPAddress(ctx context.Context, vmMacAddr string) (string, error) {
	resolveIPAddressTimeout := 2 * time.Minute
	resolveIPAddressTimeoutEnv := os.Getenv("LIMA_USERNET_RESOLVE_IP_ADDRESS_TIMEOUT")
	if resolveIPAddressTimeoutEnv != "" {
		if parsedTimeout, err := strconv.Atoi(resolveIPAddressTimeoutEnv); err == nil {
			resolveIPAddressTimeout = time.Duration(parsedTimeout) * time.Minute
		}
	}
	ctx, cancel := context.WithTimeout(ctx, resolveIPAddressTimeout)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			return "", errors.New("usernet unable to resolve IP for SSH forwarding")
		case <-ticker.C:
			leases, err := c.Leases(ctx)
			if err != nil {
				return "", err
			}

			for ipAddr, leaseAddr := range leases {
				if vmMacAddr == leaseAddr {
					return ipAddr, nil
				}
			}
		}
	}
}

func (c *Client) Leases(ctx context.Context) (map[string]string, error) {
	u := fmt.Sprintf("%s%s", c.base, "/services/dhcp/leases")
	res, err := httpclientutil.Get(ctx, c.client, u)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	dec := json.NewDecoder(res.Body)
	var leases map[string]string
	if err := dec.Decode(&leases); err != nil {
		return nil, err
	}
	return leases, nil
}

func NewClientByName(nwName string) *Client {
	endpointSock, err := Sock(nwName, EndpointSock)
	if err != nil {
		return nil
	}
	subnet, err := Subnet(nwName)
	if err != nil {
		return nil
	}
	return NewClient(endpointSock, subnet)
}

func NewClient(endpointSock string, subnet net.IP) *Client {
	return create(endpointSock, subnet, "http://lima")
}

func create(sock string, subnet net.IP, base string) *Client {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	delegate := gvproxyclient.New(client, "http://lima")
	return &Client{
		client:   client,
		delegate: delegate,
		base:     base,
		subnet:   subnet,
	}
}
