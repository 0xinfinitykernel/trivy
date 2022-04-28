package artifact

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
)

// K8sRun runs scan on kubernetes cluster
func K8sRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	if err = log.InitLogger(opt.Debug, true); err != nil {
		return err
	}

	cacheClient, err := initCache(opt)
	if err != nil {
		if errors.Is(err, errSkipScan) {
			return nil
		}
		return xerrors.Errorf("cache error: %w", err)
	}
	defer cacheClient.Close()

	// Disable DB update when using client/server
	if opt.RemoteAddr == "" {
		if err = initDB(opt); err != nil {
			if errors.Is(err, errSkipScan) {
				return nil
			}
			return xerrors.Errorf("DB error: %w", err)
		}
		defer db.Close()
	}

	iacScannerConfig, iacScannerOptions, err := initIacScannerConfig(ctx.Context, opt, cacheClient)
	if err != nil {
		return xerrors.Errorf("scanner config error: %w", err)
	}

	imageScannerConfig, imageScannerOptions, err := initImageScannerConfig(ctx.Context, opt, cacheClient)
	if err != nil {
		return xerrors.Errorf("scanner config error: %w", err)
	}

	dynamicClient, err := k8s.NewDynamicClient()
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	k8sClient := k8s.New(dynamicClient)
	k8sArtifacts, err := k8sClient.GetAllArtifactsByNamespace(ctx.Context, "default")
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	imageReports := make([]KReport, 0)
	iacReports := make([]KReport, 0)

	for _, artifact := range k8sArtifacts {
		// scan images
		for _, image := range artifact.Images {
			report, err := k8sScan(ctx.Context, image, imageScanner, imageScannerConfig, imageScannerOptions)
			if err != nil {
				return err
			}

			report, err = filter(ctx.Context, opt, report)
			if err != nil {
				return xerrors.Errorf("filter error: %w", err)
			}

			imageReports = append(imageReports, KReport{
				Namespace: artifact.Namespace,
				Kind:      artifact.Kind,
				Name:      image,
				Results:   report.Results,
			})
		}

		// scan iac
		// refactor WriteToFile, the caller should control the file lifecycle
		file, err := artifact.WriteFile()
		if err != nil {
			return xerrors.Errorf("error writing artifact to file: %w", err)
		}

		report, err := k8sScan(ctx.Context, file, filesystemStandaloneScanner, iacScannerConfig, iacScannerOptions)
		if err != nil {
			return err
		}

		report, err = filter(ctx.Context, opt, report)
		if err != nil {
			return xerrors.Errorf("filter error: %w", err)
		}

		iacReports = append(iacReports, KReport{
			Namespace: artifact.Namespace,
			Kind:      artifact.Kind,
			Name:      artifact.Name,
			Results:   report.Results,
		})

	}

	printKReportSummary(imageReports)
	printKReportSummary(iacReports)

	return nil
}

func initIacScannerConfig(ctx context.Context, opt Option, cacheClient cache.Cache) (ScannerConfig, types.ScanOptions, error) {
	// Disable OS and language analyzers
	opt.DisabledAnalyzers = append(analyzer.TypeOSes, analyzer.TypeLanguages...)

	// Scan only config files
	opt.VulnType = nil
	opt.SecurityChecks = []string{types.SecurityCheckConfig}

	// Skip downloading vulnerability DB
	opt.SkipDBUpdate = true

	return initScannerConfig(ctx, opt, cacheClient)
}

func initImageScannerConfig(ctx context.Context, opt Option, cacheClient cache.Cache) (ScannerConfig, types.ScanOptions, error) {
	opt.DisabledAnalyzers = analyzer.TypeLockfiles
	return initScannerConfig(ctx, opt, cacheClient)
}

func k8sScan(ctx context.Context, target string, initializeScanner InitializeScanner, config ScannerConfig, opts types.ScanOptions) (types.Report, error) {
	config.Target = target
	s, cleanup, err := initializeScanner(ctx, config)
	if err != nil {
		// TODO: should exit?
		log.Logger.Errorf("Unexpected error during scanning %s: %s", config.Target, err)
		return types.Report{}, nil
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("image scan failed: %w", err)
	}
	return report, nil
}

type KReport struct {
	Namespace string
	Kind      string
	Name      string
	Results   types.Results
}

func printKReportSummary(reports []KReport) {
	var columns [][]string
	for _, r := range reports {
		c := make([]string, 4)
		c[0] = r.Namespace
		c[1] = r.Kind
		c[2] = r.Name

		for _, rr := range r.Results {
			for _, vuln := range rr.Vulnerabilities {
				var critical, high, medium, low, unknown int
				switch vuln.Severity {
				case "CRITICAL":
					critical++
				case "HIGH":
					high++
				case "MEDIUM":
					medium++
				case "LOW":
					low++
				case "UNKNOWN":
					unknown++
				default:
					fmt.Println("mimi", vuln.Severity)
				}

				c[3] = fmt.Sprintf("low: %d, medium: %d, high: %d, critical: %d, unknown: %d", low, medium, high, critical, unknown)
			}

			for _, vuln := range rr.Misconfigurations {
				var critical, high, medium, low, unknown int
				switch vuln.Severity {
				case "CRITICAL":
					critical++
				case "HIGH":
					high++
				case "MEDIUM":
					medium++
				case "LOW":
					low++
				case "UNKNOWN":
					unknown++
				default:
					fmt.Println("mimi", vuln.Severity)
				}

				c[3] = fmt.Sprintf("low: %d, medium: %d, high: %d, critical: %d, unknown: %d", low, medium, high, critical, unknown)
			}
		}

		columns = append(columns, c)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.AppendBulk(columns)
	table.SetHeader([]string{
		"Namespace",
		"Resource",
		"Image",
		"Vunerabilities",
	})

	table.SetRowLine(true)
	table.Render() // Send output
}
