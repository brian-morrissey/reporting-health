import argparse
import logging
import sys
import urllib3
import json
from datetime import datetime
from datetime import timedelta
from dateutil import tz
import time
import os.path
import os

class UnexpectedHTTPResponse(Exception):
    """Used when recieving an unexpected HTTP response"""

http_client = urllib3.PoolManager()

def _parse_args():

    args = None

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--secure_url_authority",
        required=True,
        type=str,
        action="store",
        help="authority component of secure url",
    )
    parser.add_argument(
        "--api_token",
        required=True,
        type=str,
        action="store",
        help="Sysdig Secure API Token",
    )

    return parser.parse_args()

def main():
        args = _parse_args()
        arg_secure_url_authority = args.secure_url_authority
        arg_authentication_bearer = args.api_token

        # Add the authentication header
        http_client.headers["Authorization"] = f"Bearer {arg_authentication_bearer}"
        http_client.headers["Accept"] = "application/json"
        http_client.headers["Content-Type"] = "application/json"

        now_epoch = int(time.time())
        h_24_epoch = now_epoch - 86400
        d_30_epoch = now_epoch - 30 * 86400

        # Get clusters from runtime findings
        try:
            url = f"https://{arg_secure_url_authority}/api/secure-metrics/v1/vm-cve/filter/cluster?from={d_30_epoch}&to={now_epoch}&filter=context+%3D+%22runtime%22&limit=500"
            response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
        except Exception as e:
            print(f"An error occurred: {e}")
            quit()

        if response.status == 200:
            json_response_data = json.loads(response.data.decode())
            
            print(f"clusters: {json_response_data}\n\n")

            for cluster_name in json_response_data.get('values', []):
                try:
                    url = f"https://{arg_secure_url_authority}/api/secure-metrics/v1/vm-data-usage/timeseries?from={d_30_epoch}&to={now_epoch}&group=context&filter=context+%3D+%22runtime%22+and+cluster+in+%28%22{cluster_name}%22%29"
                    response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
                except Exception as e:
                    print(f"An error occurred: {e}")
                    quit()

                if response.status == 200:
                    json_response_data = json.loads(response.data.decode())
                    for result in json_response_data.get('results', []):
                        values = [point["value"] for point in result["series"]]
                        if len(values) >= 5:
                            last_5_values = values[-5:]
                            max_value = max(values)
                            if all(v == 0 or v < 0.1 * max_value for v in last_5_values):
                                print(f"Cluster {cluster_name}: Last 5 daily scanning trend values are 0 or less than 10% of the maximum value.")     

                                # Get Agent Status
                                try:
                                    url = f"https://{arg_secure_url_authority}/api/cloud/v2/dataSources/agents?limit=50&offset=0&filter={cluster_name}"
                                    response = http_client.request(method="GET", url=url, redirect=True, timeout=3)
                                except Exception as e:
                                    print(f"An error occurred: {e}")
                                    quit()
                                    
                                if response.status == 200:
                                    json_agent_data = json.loads(response.data.decode())
                                    for agent in json_agent_data['details']:
                                        print(f"\tAgent Status: {agent['clusterName']} {agent['labels']['hostname']} {agent['agentStatus']}")
                                else:
                                   raise UnexpectedHTTPResponse(
                                            f"Unexpected HTTP response status: {response.status}"
                                        )


                else:  
                    raise UnexpectedHTTPResponse(
                        f"Unexpected HTTP response status: {response.status}"
                    )
                
        else:
            raise UnexpectedHTTPResponse(
                f"Unexpected HTTP response status: {response.status}"
            )
        
if __name__ == "__main__":
    sys.exit(main())