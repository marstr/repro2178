// Copyright © 2018 Martin Strobel
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/containerservice/mgmt/2018-03-31/containerservice"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/marstr/randname"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const terraformDemoSSHPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqaZoyiz1qbdOQ8xEf6uEu1cCwYowo5FHtsBhqLoDnnp7KUTEBN+L2NxRIfQ781rxV6Iq5jSav6b2Q8z5KiseOlvKA/RF2wqU0UPYqQviQhLmW6THTpmrv/YkUCuzxDpsH7DUDhZcwySLKVVe0Qm3+5N2Ta6UYH3lsDf9R9wTP2K/+vAnflKebuypNlmocIvakFWoZda18FOmsOoIVXQ8HWFNCuw9ZCunMSN62QGamCe3dL5cXlkgHYv7ekJE15IA9aOJcM7e90oeTqo+7HTcWfdu0qQqPWY5ujyMw/llas8tsXY85LFqRnr3gJ02bAscjc477+X+j/gkpFoN1QEmt terraform@demo.tld"

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "repro2178",
	Short: "Executes a repro for https://github.com/Azure/azure-sdk-for-go/issues/2178",
	Run: func(cmd *cobra.Command, args []string) {
		var ctx context.Context
		var cancel context.CancelFunc
		if timeout, err := time.ParseDuration(viper.GetString("timeout")); err == nil {
			ctx, cancel = context.WithTimeout(context.Background(), timeout)
			defer cancel()
		} else {
			logrus.Errorf("unable to parse %s as a `time.Duration`", viper.GetString("timeout"))
			return
		}

		config, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, viper.GetString("tenant-id"))
		if err != nil {
			logrus.Errorf("Bad OAuth Config: %v", err)
			return
		}
		token, err := adal.NewServicePrincipalToken(*config, viper.GetString("client-id"), viper.GetString("client-secret"), azure.PublicCloud.ResourceManagerEndpoint)
		if err != nil {
			logrus.Errorf("Bad Service Principal Token parameters: %v", err)
			return
		}

		auth := autorest.NewBearerAuthorizer(token)

		var group resources.Group
		if g, err := getResourceGroup(ctx, auth, viper.GetString("resource-group")); err == nil {
			group = g
		} else {
			logrus.Errorf("Unable to create or get resource group %q: %v", viper.GetString("resource-group"), err)
			return
		}

		if viper.GetBool("clean-up") {
			defer func() {
				logrus.Infof("Deleting Resource Group %q - exiting the program will have no impact on deletion", *group.Name)
				deleteResourceGroup(context.Background(), auth, *group.Name)
			}()
		}

		clusterName := viper.GetString("cluster-name")
		logrus.Infof("Using Resource Group %q", clusterName)

		done := make(chan string, 4)

		executedeployKubeTest := func(ctx context.Context, includeValidation bool, podCidr *string, i uint8) {
			updatedName := fmt.Sprintf("%s-%d", clusterName, i)

			defer func() {
				done <- updatedName
			}()
			logrus.Infof("starting deployment of cluster %q", updatedName)
			if err := deployKubernetesCluster(ctx, auth, group, includeValidation, updatedName, podCidr, terraformDemoSSHPublicKey); err != nil {
				messageBuilder := bytes.NewBufferString("Failed to create cluster ")
				fmt.Fprint(messageBuilder, updatedName)
				fmt.Fprint(messageBuilder, " with PodCidr Value ")

				if podCidr == nil {
					fmt.Fprint(messageBuilder, "nil")
				} else {
					messageBuilder.WriteRune('"')
					fmt.Fprint(messageBuilder, *podCidr)
					messageBuilder.WriteRune('"')
				}
				messageBuilder.WriteString(": ")
				fmt.Fprint(messageBuilder, err)
				logrus.Error(messageBuilder.String())
				return
			}
			logrus.Info("finished deployment of cluster %q", updatedName)
		}

		executedeployKubeTest(ctx, true, nil, 0)
		executedeployKubeTest(ctx, true, to.StringPtr(""), 1)
		executedeployKubeTest(ctx, false, to.StringPtr(""), 2)
		executedeployKubeTest(ctx, true, to.StringPtr("10.24.0.0/16"), 3)

		for i := 0; i < 4; i++ {
			select {
			case <-ctx.Done():
				logrus.Error("timed out")
				return
			case name := <-done:
				logrus.Infof("finished cluster test %q", name)
			}
		}
	},
	Args: func(cmd *cobra.Command, args []string) error {
		if viper.GetString("resource-group") == "<randomly generated>" {
			viper.Set("resource-group", randname.GenerateWithPrefix("repro2178-", 6))
		}

		if viper.GetString("cluster-name") == "<randomly generated>" {
			clusterName := randname.Prefixed{
				Prefix:     "repro2178-cluster-",
				Acceptable: append(randname.LowercaseAlphabet, randname.ArabicNumerals...),
				Len:        6,
			}

			viper.Set("cluster-name", clusterName.Generate())
		}

		return cobra.NoArgs(cmd, args)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	viper.BindEnv("subscription-id", "AZURE_SUBSCRIPTION_ID", "AZ_SUBSCRIPTION_ID")
	viper.BindEnv("tenant-id", "AZURE_TENANT_ID", "AZ_TENANT_ID")
	viper.BindEnv("client-id", "AZURE_CLIENT_ID", "AZ_CLIENT_ID")
	viper.BindEnv("client-secret", "AZURE_CLIENT_SECRET", "AZ_CLIENT_SECRET")

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.repro2178.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.PersistentFlags().String("client-id", viper.GetString("client-id"), "The ID of the Service Principal being used for authentication.")
	rootCmd.PersistentFlags().String("client-secret", viper.GetString("client-secret"), "The Secret of the Service Principal being used for authentication.")
	rootCmd.PersistentFlags().StringP("subscription-id", "s", viper.GetString("subscription-id"), "The UUID of the Azure subscription to be used.")
	rootCmd.PersistentFlags().StringP("tenant-id", "t", viper.GetString("tenant-id"), "The UUID of the Azure tenant the subscription belongs to.")
	rootCmd.PersistentFlags().StringP("resource-group", "g", "<randomly generated>", "The resource group that should be created/used for the sake of reproducing this.")
	rootCmd.PersistentFlags().StringP("location", "l", "westus2", "The location to create the resource group in, should it not already exist.")
	rootCmd.PersistentFlags().StringP("timeout", "u", "10m", "A string which can be processed by `time.ParseDuration` before this repro should timeout.")
	rootCmd.PersistentFlags().BoolP("clean-up", "c", true, "Delete the resource group after finishing the repro.")

	rootCmd.Flags().StringP("cluster-name", "n", "<randomly generated>", "The name the cluster should adopt when deployed.")

	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.BindPFlags(rootCmd.Flags())
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".repro2178" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".repro2178")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

// getResourceGroup either fetches a reference to an existing Resource Group, or creates a new one.
func getResourceGroup(ctx context.Context, auth autorest.Authorizer, name string) (created resources.Group, err error) {
	client := resources.NewGroupsClient(viper.GetString("subscription-id"))
	client.Authorizer = auth

	desired := resources.Group{
		Name:     &name,
		Location: to.StringPtr(viper.GetString("location")),
	}

	return client.CreateOrUpdate(ctx, name, desired)
}

func deleteResourceGroup(ctx context.Context, auth autorest.Authorizer, name string) error {
	client := resources.NewGroupsClient(viper.GetString("subscription-id"))
	client.Authorizer = auth

	fut, err := client.Delete(ctx, name)
	if err != nil {
		return err
	}

	return fut.WaitForCompletion(ctx, client.Client)
}

func deployKubernetesCluster(ctx context.Context, auth autorest.Authorizer, group resources.Group, includeValidation bool, name string, podCidr *string, publicKey string) error {
	client := containerservice.NewManagedClustersClient(viper.GetString("subscription-id"))
	client.Authorizer = auth

	desired := containerservice.ManagedCluster{
		Location: group.Location,
		ManagedClusterProperties: &containerservice.ManagedClusterProperties{
			AgentPoolProfiles: &[]containerservice.ManagedClusterAgentPoolProfile{
				{
					Name:   to.StringPtr("default"),
					Count:  to.Int32Ptr(2),
					VMSize: containerservice.StandardDS2V2,
				},
			},
			DNSPrefix:         to.StringPtr(name),
			KubernetesVersion: to.StringPtr("1.7.7"),
			LinuxProfile: &containerservice.LinuxProfile{
				AdminUsername: to.StringPtr(name + "user"),
				SSH: &containerservice.SSHConfiguration{
					PublicKeys: &[]containerservice.SSHPublicKey{
						containerservice.SSHPublicKey{
							KeyData: &publicKey,
						},
					},
				},
			},
			NetworkProfile: &containerservice.NetworkProfile{
				NetworkPlugin:    containerservice.Azure,
				DNSServiceIP:     to.StringPtr("10.10.0.10"),
				DockerBridgeCidr: to.StringPtr("172.18.0.1/16"),
				ServiceCidr:      to.StringPtr("10.10.0.0/16"),
				PodCidr:          podCidr,
			},
		},
	}

	var fut containerservice.ManagedClustersCreateOrUpdateFuture
	var err error
	if includeValidation {
		fut, err = client.CreateOrUpdate(ctx, *group.Name, name, desired)
	} else {
		var req *http.Request
		req, err = client.CreateOrUpdatePreparer(ctx, *group.Name, name, desired)
		if err != nil {
			return err
		}
		fut, err = client.CreateOrUpdateSender(req)
	}

	if err != nil {
		return err
	}

	return fut.WaitForCompletion(ctx, client.Client)
}
