package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/square/go-jose"
)

var rootCmd = &cobra.Command{
	Use:   "td",
	Short: "Token Decoder is a cmd tool for decrypting A&G authentication tokens via your cli.",
	Long: `A Fast and Flexible Token Decoder Generator built with
                love in Go.
                Complete documentation is available in the repos readme.`,
	Run: func(cmd *cobra.Command, args []string) {
		usr, err := user.Current()
		if err != nil {
			panic(fmt.Errorf("fatal error: %w", err))
		}

		configDir := filepath.Join(usr.HomeDir, ".josectl")
		if _, err := os.Stat(configDir); os.IsNotExist(err) {
			// path/to/whatever does not exist
			os.MkdirAll(configDir, 0777)
		}
		fullConfigFilePath := filepath.Join(usr.HomeDir, "config.toml")

		viper.SetDefault("Keys", []string{})
		viper.SetConfigName("config")
		viper.SetConfigType("toml")
		viper.AddConfigPath("$HOME/.josectl")
		err = viper.ReadInConfig()

		if err != nil {
			err := viper.WriteConfigAs(fullConfigFilePath)

			if err != nil {
				panic(fmt.Errorf("fatal error unable to create config.toml file: %w", err))
			}
		}

		token, _ := cmd.Flags().GetString("token")
		secret, _ := cmd.Flags().GetString("secret")

		if token == "" {
			fmt.Fprintln(os.Stderr, "Missing token to decode")
			os.Exit(1)
		}

		if secret == "" {
			fmt.Fprintln(os.Stderr, "Missing secret to decode token with")
			os.Exit(1)
		}

		jwe, _ := jose.ParseEncrypted(token)
		decryptedJWT, _ := jwe.Decrypt(secret)
		jwtStr := string(decryptedJWT)

		tmp := jwtStr[strings.IndexByte(jwtStr, '.')+1:]
		claim := tmp[:strings.IndexByte(tmp, '.')] + "=="

		rawDecodedText, err := base64.StdEncoding.DecodeString(claim)
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(rawDecodedText)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("token", "t", "", "The token to decrypt")
	rootCmd.Flags().StringP("secret", "s", "", "The secret to use to decrypt the token")
}
