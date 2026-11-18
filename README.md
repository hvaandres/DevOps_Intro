# DevOps_Intro

The primary objective of this project is to enhance people's familiarity with DevOps tools by utilizing real-life scenarios. To achieve this goal, each project will comprise a blog post and a video that will offer valuable insights into the daily routines of DevOps Engineers. Additionally, this will be an open-source project, enabling individuals to contribute their ideas and insights to this initiative.

## Project Structure
Each project will be structured as follows:
- A blog post that will be published on [Medium](https://medium.com/@ithvaandres)
- A video that will be published on [YouTube](https://www.youtube.com/channel/hvaandres)
- A GitHub repository that will contain the code and the [documentation](https://ithvaandres.github.io/DevOps_Intro)

## Project List
- [x] Tools
    - [x] Git
    - [x] GitHub
    - [x] Markdown
    - [x] Docker
    - [x] Kubernetes
        - [x] Helm
        - [x] Kustomize
        - [x] Minikube
        - [x] Kind
        - [x] K9S
    - [x] Github Actions
        - [x] CI
        - [x] CD
        - [x] Secrets
    - [x] Terraform
    - [x] AWS
    - [x] Azure
    - [x] GCP
    - [x] Prometheus
    - [x] Grafana
    - [x] ELK
    - [x] Istio
    - [x] Argo
    - [x] Python
    - [x] Bash

## Terraform Azure setup

See the [Terraform Make command reference](Terraform/intro.md) for Azure login,
subscription selection, permissions, and creating/testing a Terraform state
backend. All targets run from the repository root without `-C`:

```bash
make help
make azure-login
make azure-subscription
make resource-group-create SUBSCRIPTION_ID="<subscription UUID>" RESOURCE_GROUP=rg-my-test LOCATION=eastus2
```

The same entry point provides `make azure-permissions`, `make backend-create`,
`make backend-test`, and `make test`. See the guide for required variables and
confirmation details. Resource group creation needs no storage account.

Deployment-specific documentation:
- [Private Link networking](Terraform/Azure/tfm-privateLink-network/README.md)
- [Key Vault](Terraform/Azure/tfm-keyvault/README.md)

## Contribution
If you would like to contribute to this project, please follow the steps below:
1. Fork the repository
2. Create a new branch
3. Make your changes
4. Create a pull request
5. If you are using a different tool, please create a new folder:
    5.1 Create a new folder with the name of the tool
    5.2 Create a new file called `readMe.md` and add the following content:
    ```
    #### Intro
    #### Prerequisites
    #### Installation
    #### Usage
    ```
    5.3 Add as much information about your project as possible to make it easier for other people to understand and use it.


## License
This project is licensed under the MIT License - see the [LICENSE](https://ithvaandres.github.io/DevOps_Intro/LICENSE.txt) file for details.

## Acknowledgments
- Every Developer that contribute to this project by sharing their knowledge and experience with the community will be mentioned in the blog post and the video.

## Contact
If you have any questions, please feel free to contact me at hello@aharo.dev.

## Disclaimer
This project is not affiliated with any of the companies mentioned above. The content of this project is solely for educational purposes.

## Author
- [Andres Haro](https://www.aharo.dev)

## Social Media
- [LinkedIn](https://www.linkedin.com/in/ithvaandres/)
- [Twitter](https://twitter.com/madebyux)
- [Instagram](https://www.instagram.com/hvaandres)
- [Podcast](https://open.spotify.com/show/1ImqedW8QKl5XI1HJUDQJR)
- [Medium](https://medium.com/@ithvaandres)

## Donate
If you would like to support this project, please consider donating to the following platforms:
- [Patreon](https://www.patreon.com/ithvaandres)
