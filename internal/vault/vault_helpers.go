package vault

import (
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"log"
	"path"
	"strings"
	"time"
)

type secretV2Metadata struct {
	CasRequired        bool                       `json:"cas_required"`
	CreatedTime        time.Time                  `json:"created_time"`
	CurrentVersion     int                        `json:"current_version"`
	CustomMetadata     map[string]string          `json:"custom_metadata"`
	DeleteVersionAfter string                     `json:"delete_version_after"`
	MaxVersions        int                        `json:"max_versions"`
	OldestVersion      int                        `json:"oldest_version"`
	UpdatedTime        time.Time                  `json:"updated_time"`
	Versions           map[string]secretV2Version `json:"versions"`
}

type secretV2Version struct {
	CreatedTime  time.Time `json:"created_time"`
	DeletionTime string    `json:"deletion_time"`
	Destroyed    bool      `json:"destroyed"`
}

func prefixSecretPath(secretPath, prefix string, c *api.Client) (string, error) {
	partialPath := sanitizePath(secretPath)
	mountPath, v2, err := isKVv2(partialPath, c)
	if err != nil {
		log.Println("error checking", secretPath, "mount type:", err)
		return "", err
	}
	if !v2 {
		log.Println("path not using KV v2 mount, metadata not supported:", secretPath)
		return "", fmt.Errorf("unsupported mount")
	}

	return addPrefixToKVPath(partialPath, mountPath, prefix), nil
}

func secretMetadataPath(secretPath string, c *api.Client) (string, error) {
	return prefixSecretPath(secretPath, "metadata", c)
}

func secretDataPath(secretPath string, c *api.Client) (string, error) {
	return prefixSecretPath(secretPath, "data", c)
}

func secretDeletePath(secretPath string, c *api.Client) (string, error) {
	return prefixSecretPath(secretPath, "delete", c)
}

func isSecretDeleted(secret *api.Secret) (bool, error) {
	if secret.Data == nil {
		return false, fmt.Errorf("missing secret data")
	}

	metadata := secret.Data["metadata"]
	if metadata == nil {
		return false, fmt.Errorf("missing secret metadata")
	}

	deletionDate := metadata.(map[string]interface{})["deletion_time"]
	return deletionDate == nil, nil
}

func addPrefixToKVPath(p, mountPath, apiPrefix string) string {
	if p == mountPath || p == strings.TrimSuffix(mountPath, "/") {
		return path.Join(mountPath, apiPrefix)
	}

	tp := strings.TrimPrefix(p, mountPath)
	for {
		// If the entire mountPath is included in the path, we are done
		if tp != p {
			break
		}
		// Trim the parts of the mountPath that are not included in the
		// path, for example, in cases where the mountPath contains
		// namespaces which are not included in the path.
		partialMountPath := strings.SplitN(mountPath, "/", 2)
		if len(partialMountPath) <= 1 || partialMountPath[1] == "" {
			break
		}
		mountPath = strings.TrimSuffix(partialMountPath[1], "/")
		tp = strings.TrimPrefix(tp, mountPath)
	}

	return path.Join(mountPath, apiPrefix, tp)
}

func isKVv2(path string, client *api.Client) (string, bool, error) {
	mountPath, version, err := kvPreflightVersionRequest(client, path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

func kvPreflightVersionRequest(client *api.Client, path string) (string, int, error) {
	// We don't want to use a wrapping call here so save any custom value and
	// restore after
	currentWrappingLookupFunc := client.CurrentWrappingLookupFunc()
	client.SetWrappingLookupFunc(nil)
	defer client.SetWrappingLookupFunc(currentWrappingLookupFunc)
	currentOutputCurlString := client.OutputCurlString()
	client.SetOutputCurlString(false)
	defer client.SetOutputCurlString(currentOutputCurlString)
	currentOutputPolicy := client.OutputPolicy()
	client.SetOutputPolicy(false)
	defer client.SetOutputPolicy(currentOutputPolicy)

	r := client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, default to
		// version 1
		if resp != nil {
			if resp.StatusCode == 404 {
				return "", 1, nil
			}

			// if the original request had the -output-curl-string or -output-policy flag,
			if (currentOutputCurlString || currentOutputPolicy) && resp.StatusCode == 403 {
				// we provide a more helpful error for the user,
				// who may not understand why the flag isn't working.
				err = fmt.Errorf(
					`This output flag requires the success of a preflight request 
to determine the version of a KV secrets engine. Please 
re-run this command with a token with read access to %s`, path)
			}
		}

		return "", 0, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	if secret == nil {
		return "", 0, errors.New("nil response from pre-flight request")
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath = mountPathRaw.(string)
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
}

// sanitizePath removes any leading or trailing things from a "path".
func sanitizePath(s string) string {
	return ensureNoTrailingSlash(ensureNoLeadingSlash(s))
}

// ensureNoLeadingSlash ensures the given string does not have a leading slash.
func ensureNoLeadingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	return s
}

// ensureNoTrailingSlash ensures the given string does not have a trailing slash.
func ensureNoTrailingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
