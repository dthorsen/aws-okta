package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/99designs/keyring"
	"github.com/dthorsen/aws-okta/lib"
	"github.com/spf13/cobra"
)

// envCmd represents the env command
var envCmd = &cobra.Command{
	Use:    "env <profile>",
	Short:  "env will print shell `export` commands to set up your environment for AWS CLI",
	RunE:   envRun,
	PreRun: envPre,
}

func init() {
	RootCmd.AddCommand(envCmd)
	envCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", 12*time.Hour, "Expiration time for okta role session")
	envCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", 12*time.Hour, "Expiration time for assumed role")
}

func envPre(cmd *cobra.Command, args []string) {
	sessionTTL = 12 * time.Hour
	assumeRoleTTL = 12 * time.Hour
	if err := loadDurationFlagFromEnv(cmd, "session-ttl", "AWS_SESSION_TTL", &sessionTTL); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to parse duration from AWS_SESSION_TTL")
	}

	if err := loadDurationFlagFromEnv(cmd, "assume-role-ttl", "AWS_ASSUME_ROLE_TTL", &assumeRoleTTL); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to parse duration from AWS_ASSUME_ROLE_TTL")
	}
}

func envRun(cmd *cobra.Command, args []string) error {

	if len(args) == 0 {
		return ErrTooFewArguments
	}

	profile := args[0]

	config, err := lib.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	if _, ok := profiles[profile]; !ok {
		return fmt.Errorf("Profile '%s' not found in your aws config", profile)
	}

	opts := lib.ProviderOptions{
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
	}

	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}

	kr, err := lib.OpenKeyring(allowedBackends)
	if err != nil {
		return err
	}

	p, err := lib.NewProvider(kr, profile, opts)
	if err != nil {
		return err
	}

	creds, err := p.Retrieve()
	if err != nil {
		return err
	}

	env := environ(os.Environ())
	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")

	if region, ok := profiles[profile]["region"]; ok {
		env.Set("AWS_DEFAULT_REGION", region)
		env.Set("AWS_REGION", region)
	}

	env.Set("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	env.Set("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)

	if creds.SessionToken != "" {
		env.Set("AWS_SESSION_TOKEN", creds.SessionToken)
		env.Set("AWS_SECURITY_TOKEN", creds.SessionToken)
	}

	fmt.Printf("export AWS_ACCESS_KEY_ID=%v\n", creds.AccessKeyID)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%v\n", creds.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=%v\n", creds.SessionToken)
	return nil
}
