# mutli-cloud-threat-model-capstone

Phase 1 threat model for a fictional internal GenAI support assistant using Azure, AWS, and Google Cloud.

- [Threat model report](Phase1_Multi_Cloud_Threat_Model.md)
- [Python generator](threat_model.py)

Run from the repository root with Python 3. No third-party packages or cloud credentials are required.

```sh
python threat_model.py
```

The script validates model references and regenerates the Markdown report in the current directory. Risk scores are training estimates, and proposed controls require validation in the chosen environment.
