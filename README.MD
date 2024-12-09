# Check cluster VM runtime reporting status

## Usage:

```sh
python reporting-health.py --secure_url_authority app.us4.sysdig.com --api_token xyz

## Output:

Cluster eks-test1: Okay

Cluster eks-test2: Last 5 daily scanning trend values are 0 or less than 10% of the maximum value.