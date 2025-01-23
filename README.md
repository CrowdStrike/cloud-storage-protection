<p align="center">
   <img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png" alt="CrowdStrike logo" width="500"/>
</p>

# Cloud Storage Protection

This repository demonstrates different ways to leverage CrowdStrike's QuickScan Pro APIs to protect Cloud Storage solutions. Through these examples, you'll learn how to implement both real-time and on-demand malware scanning for your cloud storage.

QuickScan Pro is an advanced file analysis tool that provides comprehensive threat detection through in-depth analysis using CrowdStrike Intelligence,
supporting over 60 file formats and offering features like sandbox detonations, YARA rules, and machine learning-based detection.

## Solution Overview

This repository provides implementations for QuickScan Pro, offering advanced malware protection for your cloud storage across multiple cloud providers:

### Protection Methods

- **Real-time Storage Protection**: Scan files automatically upon upload
- **Existing Storage Protection**: Add scanning capabilities to already deployed storage solutions
- **On-demand Scanning**: Scan content from existing storage solutions before implementing protection

## Implementation Options

The repository is organized by cloud provider, with each directory containing:

- Terraform configurations for deployment
- Command line helper scripts
- Step-by-step tutorials

### Cloud Provider Examples

- [AWS Examples](./AWS/README.md)
- [Azure Examples](./Azure/README.md)
- [GCP Examples](./GCP/README.md)

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on how to submit pull requests.

## Support

Cloud Storage Protection is a community-driven, open source project designed to provide examples on how to leverage the CrowdStrike QuickScan APIs for cloud storage protection. While not a formal CrowdStrike product, Cloud Storage Protection is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional support, please see the [SUPPORT.md](SUPPORT.md) file.

## License

This project is licensed under the [MIT License](LICENSE).
