from flask import Flask, request, jsonify
import json
import base64
import os  

app = Flask(__name__)

# Use an environment variable for the label selector key
LABEL_KEY = os.getenv('MUTATING_WEBHOOK_LABEL_KEY')
print("Filtering on LABEL_KEY: ", LABEL_KEY)

@app.route('/mutate-pods', methods=['POST'])
def mutate_pod():
    # Parse the AdmissionReview request
    request_json = request.get_json()
    pod = request_json["request"]["object"]

    # Check for the presence of the environment variable label key and if the Pod matches the specific label selector
    label_value = pod["metadata"]["labels"].get(LABEL_KEY) if LABEL_KEY else None
    print("Pod label value: ", label_value)

    # Conditions to check if mutation should be applied
    # 1. If LABEL_KEY is not set, proceed without label filtering
    # 2. If LABEL_KEY is set, only proceed if the Pod has the specified label
    if not LABEL_KEY or label_value:
        print("Mutating Pod, label match (or no KEY specified): ", pod["metadata"]["name"])
        # Check if there are no existing node selectors or affinities
        if not pod["spec"].get("nodeSelector") and not pod["spec"].get("affinity"):
            print("No nodeSelector or affinity found, applying mutation.")
            # Inject node affinity
            affinity_patch = {
                "op": "add",
                "path": "/spec/affinity",
                "value": {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [
                                {
                                    "matchExpressions": [
                                        {
                                            "key": "kubernetes.io/arch",
                                            "operator": "In",
                                            "values": ["arm64", "amd64"]
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            }

            # Construct the admission response with patch
            admission_response = {
                "response": {
                    "uid": request_json["request"]["uid"],
                    "allowed": True,
                    "patch": base64.b64encode(json.dumps([affinity_patch]).encode()).decode(),
                    "patchType": "JSONPatch"
                }
            }

            print("AdmissionResponse: ", admission_response)
            return jsonify(admission_response)

    # If the Pod does not match the criteria or mutation should not be applied, allow it without modification
    print("No mutation applied, allowing Pod: ", pod["metadata"]["name"])
    return jsonify({"response": {"uid": request_json["request"]["uid"], "allowed": True}})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port='5050', ssl_context=('./tls.crt', './tls.key'))  # Ensure proper SSL context in production



#    app.run(debug=True, host='0.0.0.0', port='5050') #, ssl_context=('path/to/tls.crt', 'path/to/tls.key'))
