package main

import (
	"bytes"
	"flag"
	"github.com/kevinburke/ssh_config"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strings"
	"syscall"
)

var goodBins = map[string]bool{
	"35bc8ec3e59b4c271883b9140643b62c": true,
	"00ec5ac263c25ffacfab9eb739e32521": true,//freebsd amd64 mosh-1.3.2_15
}


func main() {
	log.SetFlags(log.Lmicroseconds|log.Llongfile)

	clientPath, err := exec.LookPath("mosh-client")
	if err != nil {
		log.Fatal(err)
	}

	serverEnv := flag.String("e", "", "server env")
	flag.Parse()

	if len(flag.Args()) < 2 {
		flag.Usage()
		log.Fatal()
	}
	host, args := flag.Arg(0), flag.Args()[1:]


	//@todo maybe add unencrypted key
	sock, err := net.DialUnix("unix", nil, &net.UnixAddr{
		Name: os.Getenv("SSH_AUTH_SOCK"),
		Net:  "unix",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sock.Close()
	sshAgent := agent.NewClient(sock)


	//@todo maybe use parsed known_hosts
	userName := func() string {
		sshUser := ssh_config.Get(host, "User")
		if len(sshUser) != 0 {
			return sshUser
		}

		curUser, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		return curUser.Username
	}()

	conf := &ssh.ClientConfig{
		User:            userName,
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(sshAgent.Signers)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	port := "22"
	if sshPort := ssh_config.Get(host, "Port"); len(sshPort) != 0 {
		port = sshPort
	}
	if sshHost := ssh_config.Get(host, "Hostname"); len(sshHost) != 0 {
		host = sshHost
	}
	conn, err := ssh.Dial("tcp", host+":"+port, conf)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	sysName, machName := func() (string, string) {
		sess, err := conn.NewSession()
		if err != nil {
			log.Fatal(err)
		}
		defer sess.Close()
		out, err := sess.Output("uname -s; uname -m")
		if err != nil {
			log.Fatal(err)
		}
		outs := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(outs) != 2 {
			log.Fatal(outs)
		}
		return strings.ToLower(outs[0]), strings.ToLower(outs[1])
	}()
	log.Printf("discovered system:%q machine:%q", sysName, machName)

	//@todo configure PATH paths
	binName := func() string {
		sess, err := conn.NewSession()
		if err != nil {
			log.Fatal(err)
		}
		defer sess.Close()
		moshServerNames := "mosh-server mosh-server-" + sysName + "-" + machName
		path := "$(dirname $(which which)):$HOME:$HOME/bin:$HOME/homebrew/bin:/usr/local/bin"
		cmd := "PATH=" + path + " which -a " + moshServerNames + " 2>/dev/null | xargs "
		if sysName == "freebsd" {
			cmd += "md5 -r"
		} else {
			cmd += "--no-run-if-empty md5sum"
		}
		out, err := sess.CombinedOutput(cmd)
		if err != nil {
			log.Fatal(err, string(out))
		}
		log.Println(cmd, string(out))

		outs := strings.Split(string(out), "\n")
		if len(outs) < 1 {
			log.Fatal(outs)
		}
		for _, whichStr := range outs {
			if len(whichStr) == 0 {
				continue
			}
			whichParts := regexp.MustCompile("\\s+").Split(whichStr, -1)
			if len(whichParts) != 2 {
				log.Fatal(whichParts)
			}
			if goodBins[whichParts[0]] {
				return whichParts[1]
			}
		}
		return ""
	}()
	if len(binName) == 0 {
		binName = "mosh-server-"+sysName+"-"+machName
		clientPath, err := exec.LookPath(binName)
		if err != nil {
			log.Fatal(err)
		}
		fSrc, err := os.Open(clientPath)
		if err != nil {
			log.Fatal(err)
		}
		sftpClient, err := sftp.NewClient(conn)
		if err != nil {
			log.Fatal(err)
		}
		fDst, err := sftpClient.Create(binName)
		if err != nil {
			log.Fatal(err)
		}
		_, err = io.Copy(fDst, fSrc)
		if err != nil {
			log.Fatal(err)
		}
		fSrc.Close()
		fi, err := fDst.Stat()
		if err != nil {
			log.Fatal(err)
		}
		err = fDst.Chmod(fi.Mode()|0100)
		if err != nil {
			log.Fatal(err)
		}
		fDst.Close()
		binName = "$HOME/" + binName
	}

	argsStr := strings.Join(args, " ")

	port, key := func() (string, string) {
		sess, err := conn.NewSession()
		if err != nil {
			log.Fatal(err)
		}
		defer sess.Close()

		cmd := binName + " new -i 0.0.0.0 -- " + argsStr
		//if getenv := os.Getenv("LC_ALL"); len(getenv) != 0 {
		//	cmd = "LC_ALL=" + getenv + " " + cmd
		//}
		//if getenv := os.Getenv("TERM"); len(getenv) != 0 {
		//	cmd = "TERM=" + getenv + " " + cmd
		//}
		cmd = *serverEnv + " " + cmd

		var b bytes.Buffer
		sess.Stderr = &b

		//r, err := sess.StderrPipe()
		//if err != nil {
		//	log.Fatal(err)
		//}
		//go io.Copy(os.Stdout, r)
		out, err := sess.Output(cmd)
		//out, err := sess.CombinedOutput(cmd)
		if err != nil {
			//stderr, err2 := ioutil.ReadAll(r)
			//log.Fatal(cmd, err, string(out), string(stderr), err2)
			log.Fatal(cmd, err, string(out))
		}
		parts := strings.Split(strings.TrimSpace(string(out)), " ")
		if len(parts) != 4 {
			log.Fatal(string(out))
		}
		log.Println("started", cmd, parts[2], parts[3], string(out), "-=-", b.String())
		return parts[2], parts[3]
	}()
	err = sock.Close()
	err = conn.Close()

	//@todo MOSH_PREDICTION_DISPLAY
	err = syscall.Exec(clientPath, []string{clientPath, ip, port}, append([]string{"MOSH_KEY=" + key}, os.Environ()...))
	log.Fatal(err)
}
