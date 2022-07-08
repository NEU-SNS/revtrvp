from typing import Reversible
import requests
import sys
import argparse
import time

def run_revtr_to_source(source):

    '''
    curl -XPOST -k -H "Revtr-Key:dummy" https://revtr.ccs.neu.edu/api/v1/revtr --data '{"revtrs":[{"src":"216.66.68.179", "dst":"ple2.planet-lab.eu"}]}'
    '''
    revtr_key = "dummy"
    while True:
        resp = requests.post(
            f"https://revtr.ccs.neu.edu/api/v1/revtr",
            headers={"Revtr-Key":"dummy"},
            json={
                "revtrs": [
                    {
                        "src": source,
                        "dst": "1.1.1.1",
                    }
                ],
                },
        )
        if resp.status_code == 200:
            print(resp.json())
            break
        else:
            print(resp.text)
            time.sleep(30)
            
    



if __name__ == "__main__":

    ######################################################################
    ## Parameters
    ######################################################################
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--source", help="source to which run reverse traceroutes, format X.X.X.X", type=str)

    args = parser.parse_args()

    if not args.source:
        print(parser.error("source is mandatory"))
        exit(1)

    source = args.source
    run_revtr_to_source(source)


