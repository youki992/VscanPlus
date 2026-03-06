package main

import (
	"fmt"
	"runtime"

	"github.com/projectdiscovery/gologger"
	"github.com/youki992/VscanPlus/pkg/aiassist"
	naabuRunner "github.com/youki992/VscanPlus/pkg/naabu/v2/pkg/runner"
)

func main() {
	options := naabuRunner.ParseOptions()
	if runtime.GOOS == "windows" {
		options.NoColor = true
	}

	scanExecuted := false
	if !options.AIOnly {
		runner, err := naabuRunner.NewRunner(options)
		if err != nil {
			gologger.Fatal().Msgf("Could not create runner: %s\n", err)
		}
		err = runner.RunEnumeration()
		if err != nil {
			gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
		}
		gologger.Info().Msg("Port scan over,web scan starting")
		err = runner.Httpxrun()
		if err != nil {
			gologger.Fatal().Msgf("Could not run httpRunner: %s\n", err)
		}
		scanExecuted = true
	}

	if options.AIEnable {
		evidenceFile := options.Output
		if scanExecuted && options.Output != "" {
			evidenceFile = "port." + options.Output
		}

		report, err := aiassist.Run(aiassist.Request{
			BaseURL:      options.AIBaseURL,
			APIKey:       options.AIAPIKey,
			Model:        options.AIModel,
			Targets:      options.Host,
			HostsFile:    options.HostsFile,
			Ports:        options.Ports,
			TopPorts:     options.TopPorts,
			OutputFile:   evidenceFile,
			Prompt:       options.AIPrompt,
			MaxEvidence:  options.AIMaxEvidence,
			ScanExecuted: scanExecuted,
		})
		if err != nil {
			gologger.Fatal().Msgf("AI assistant failed: %s\n", err)
		}
		if err := aiassist.SaveReport(options.AIOutput, report); err != nil {
			gologger.Fatal().Msgf("AI report write failed: %s\n", err)
		}
		gologger.Info().Msgf("AI decision report saved: %s", options.AIOutput)
		fmt.Println(report)
	}
}
