// backend/deployer/interface.go
package deployer

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"cert-manager/config"
)

// 以下是K8s相关的导入，实际使用时需要添加
/*
import (
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)
*/

type Deployer interface {
	Name() string
	Deploy(ctx context.Context, cert *config.Certificate, config config.DeploymentConfig) error
	TestConnection(ctx context.Context, config config.DeploymentConfig) error
}

// SSH部署器实现
type SSHDeployer struct{
	configManager *config.ConfigManager
}

func NewSSHDeployer(cm *config.ConfigManager) *SSHDeployer {
	return &SSHDeployer{configManager: cm}
}

func (s *SSHDeployer) Name() string {
	return "ssh"
}

func (s *SSHDeployer) getServerConfig(serverID string) (*config.ServerConfig, error) {
	server, ok := s.configManager.GetServer(serverID)
	if !ok {
		return nil, fmt.Errorf("server not found: %s", serverID)
	}
	return server, nil
}

func (s *SSHDeployer) Deploy(ctx context.Context, cert *config.Certificate, config config.DeploymentConfig) error {
	serverConfig, err := s.getServerConfig(config.ServerID)
	if err != nil {
		return err
	}
	
	var auth ssh.AuthMethod
	if serverConfig.AuthType == "key" {
		key, err := ssh.ParsePrivateKey([]byte(serverConfig.SSHKey))
		if err != nil {
			return err
		}
		auth = ssh.PublicKeys(key)
	} else {
		auth = ssh.Password(serverConfig.Password)
	}
	
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port), &ssh.ClientConfig{
		User:            serverConfig.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 生产环境应使用known_hosts
	})
	if err != nil {
		return err
	}
	defer client.Close()
	
	// 确保目标路径存在
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	if err := session.Run(fmt.Sprintf("mkdir -p %s", config.TargetPath)); err != nil {
		session.Close()
		return fmt.Errorf("failed to create target directory: %v", err)
	}
	session.Close()
	
	// 创建临时文件
	certPath := filepath.Join(config.TargetPath, "cert.pem")
	keyPath := filepath.Join(config.TargetPath, "key.pem")
	
	// 上传证书
	if err := s.uploadFile(client, certPath, cert.CertPEM); err != nil {
		return err
	}
	if err := s.uploadFile(client, keyPath, cert.KeyPEM); err != nil {
		return err
	}
	
	// 执行重启命令
	if len(config.Commands) > 0 {
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()
		
		cmd := strings.Join(config.Commands, " && ")
		if err := session.Run(cmd); err != nil {
			return fmt.Errorf("command failed: %v", err)
		}
	}
	
	return nil
}

func (s *SSHDeployer) TestConnection(ctx context.Context, config config.DeploymentConfig) error {
	serverConfig, err := s.getServerConfig(config.ServerID)
	if err != nil {
		return err
	}
	
	var auth ssh.AuthMethod
	if serverConfig.AuthType == "key" {
		key, err := ssh.ParsePrivateKey([]byte(serverConfig.SSHKey))
		if err != nil {
			return err
		}
		auth = ssh.PublicKeys(key)
	} else {
		auth = ssh.Password(serverConfig.Password)
	}
	
	// 测试SSH连接
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port), &ssh.ClientConfig{
		User:            serverConfig.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	
	// 测试执行简单命令
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	
	if err := session.Run("echo 'Connection test successful'"); err != nil {
		return err
	}
	
	return nil
}

func (s *SSHDeployer) uploadFile(client *ssh.Client, path, content string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	
	w, err := session.StdinPipe()
	if err != nil {
		return err
	}
	
	go func() {
		defer w.Close()
		fmt.Fprint(w, content)
	}()
	
	if err := session.Run(fmt.Sprintf("cat > %s", path)); err != nil {
		return err
	}
	
	return nil
}

// K8s部署器实现（暂时注释，需要K8s依赖）
/*
type K8sDeployer struct {
	clientset *kubernetes.Clientset
}

func (k *K8sDeployer) Name() string {
	return "k8s"
}

func (k *K8sDeployer) Deploy(ctx context.Context, cert *core.Certificate, config config.DeploymentConfig) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.K8sConfig.SecretName,
			Namespace: config.K8sConfig.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte(cert.CertPEM),
			"tls.key": []byte(cert.KeyPEM),
		},
	}
	
	_, err := k.clientset.CoreV1().Secrets(config.K8sConfig.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			_, err = k.clientset.CoreV1().Secrets(config.K8sConfig.Namespace).Create(ctx, secret, metav1.CreateOptions{})
		}
	}
	return err
}

func (k *K8sDeployer) TestConnection(ctx context.Context, config config.DeploymentConfig) error {
	// 测试K8s连接
	_, err := k.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	return err
}
*/