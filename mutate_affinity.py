from flask import Flask, request, jsonify
import json
import base64
import os
import logging
import datetime
from kubernetes import client, config

# Import the required libraries for generating the TLS certificate
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# Placeholder function to generate or rotate the TLS certificate
def generate_or_rotate_tls_certificate(namespace, secret_name):
  
    core_v1_api = client.CoreV1Api()

    # Check if the Secret already exists
    try:
        secret = core_v1_api.read_namespaced_secret(secret_name, namespace)
        logging.info("TLS secret already exists. Consider rotation logic here.")
        # Here, you could add logic to check the certificate's expiry and decide whether to rotate
    except client.exceptions.ApiException as e:
        if e.status != 404:
            logging.warning("Failed to check if TLS Secret exists:", e)
            return
        
        # Secret does not exist, so let's create it
        # Generate private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Generate a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Florida"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Miami"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CAST AI"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mutate-affinity-service.castai-agent.svc"),
        ])
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 1 year
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"mutate-affinity-service.castai-agent.svc")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Convert the private key and certificate to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

        # Create a Kubernetes Secret with the TLS data
        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name=secret_name),
            type="kubernetes.io/tls",
            data={
                "tls.crt": base64.b64encode(certificate_pem).decode("utf-8"),
                "tls.key": base64.b64encode(private_key_pem).decode("utf-8"),
            }
        )
        core_v1_api.create_namespaced_secret(namespace, secret)
        logging.info("Created TLS secret")
    pass

# Placeholder function to load Kubernetes config
def load_kubernetes_config():
    # Depending on where your application runs, load the appropriate kube config
    try:
        config.load_incluster_config()  # Inside K8s cluster
    except config.ConfigException:
        config.load_kube_config()  # Outside K8s cluster (e.g., for local development)

def load_tls_data(namespace, secret_name):
    logging.info("Loading TLS material from secret...")
    
    core_v1_api = client.CoreV1Api()
    
    try:
        secret = core_v1_api.read_namespaced_secret(secret_name, namespace)
        logging.info("TLS secret found. Extracting certificate and key.")
        
        # Decode and write the TLS certificate and key to files
        cert_data = base64.b64decode(secret.data['tls.crt']).decode('utf-8')
        key_data = base64.b64decode(secret.data['tls.key']).decode('utf-8')
        
        with open('mutate-affinity-service.crt', 'w') as cert_file:
            cert_file.write(cert_data)
        
        with open('mutate-affinity-service.key', 'w') as key_file:
            key_file.write(key_data)
        
        logging.info("Certificate and key have been written to files, ready to use.")
        
    except client.exceptions.ApiException as e:
        logging.error("Error retrieving TLS secret: %s" % e)
        # If the secret couldn't be found or another error occurred, handle appropriately.
        # This could include generating the secret if not found, as in generate_or_rotate_tls_certificate.
        # For simplicity, we'll exit the application here.
        return False

    return True # all good

def update_ca_bundle(namespace, secret_name, mutating_webhook_configuration_name):
    core_v1_api = client.CoreV1Api()
    admission_api = client.AdmissionregistrationV1Api()

    # Read the TLS secret to get the CA bundle
    secret = core_v1_api.read_namespaced_secret(secret_name, namespace)
    ca_bundle = secret.data['tls.crt']  # Assuming 'tls.crt' is your CA bundle

    # Get the current MutatingWebhookConfiguration
    webhook_configuration = admission_api.read_mutating_webhook_configuration(mutating_webhook_configuration_name)
    
    # Update the CA bundle for each webhook in the configuration
    for webhook in webhook_configuration.webhooks:
        webhook.client_config.ca_bundle = ca_bundle

    # Update the MutatingWebhookConfiguration
    admission_api.replace_mutating_webhook_configuration(mutating_webhook_configuration_name, webhook_configuration)
    logging.info(f"Updated CA bundle in {mutating_webhook_configuration_name}")




# Initialize the webhook TLS certificate and key
def initialize_webhook_tls():
    logging.info("Initializing webhook TLS...")
    load_kubernetes_config()
    logging.info("Kubernetes config loaded.")

    # TODO: get the namespace and secret name from environment variables
    namespace = "castai-agent"
    secret_name = "mutate-affinity-tls"
    mutating_webhook_configuration_name = "mutate-affinity-webhook"

    generate_or_rotate_tls_certificate(namespace, secret_name)
    logging.info("TLS certificate setup completed.")

    # Load the TLS data from the Secret
    if not load_tls_data(namespace, secret_name):
        logging.error("Failed to load TLS data from Secret. Exiting.")
        exit(1)

    update_ca_bundle(namespace, secret_name, mutating_webhook_configuration_name)

    logging.info("TLS initialization complete.")


# Use an environment variable for the label selector key
LABEL_KEY = os.getenv('MUTATING_WEBHOOK_LABEL_KEY')
if LABEL_KEY:
    logging.info("Filtering on LABEL_KEY: %s" % LABEL_KEY)

@app.route('/mutate-pods', methods=['POST'])
def mutate_pod():
    # Parse the AdmissionReview request
    request_json = request.get_json()
    pod = request_json["request"]["object"]

    # Check for the presence of the environment variable label key and if the Pod matches the specific label selector
    label_value = pod["metadata"]["labels"].get(LABEL_KEY) if LABEL_KEY else None
    if label_value:
        logging.info("Pod label value: %s" % label_value)

    # Conditions to check if mutation should be applied
    # 1. If LABEL_KEY is not set, proceed without label filtering
    # 2. If LABEL_KEY is set, only proceed if the Pod has the specified label
    if not LABEL_KEY or label_value:
        if pod["metadata"]["name"]:
            logging.info("Mutating Pod, label match (or no KEY specified): %s" % pod["metadata"]["name"])

        # Check if there are no existing node selectors or affinities
        if not pod["spec"].get("nodeSelector") and not pod["spec"].get("affinity"):
            logging.info("No nodeSelector or affinity found, applying mutation.")
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
                "apiVersion": "admission.k8s.io/v1",  
                "kind": "AdmissionReview",   
                "response": {
                    "uid": request_json["request"]["uid"],
                    "allowed": True,
                    "patch": base64.b64encode(json.dumps([affinity_patch]).encode()).decode(),
                    "patchType": "JSONPatch"
                }
            }

            logging.info("AdmissionResponse: %s " % admission_response)
            return jsonify(admission_response)

    # If the Pod does not match the criteria or mutation should not be applied, allow it without modification
    if pod["metadata"]["name"]:
        logging.info("No mutation applied, allowing Pod: %s " % pod["metadata"]["name"])

    return jsonify({
        "apiVersion": "admission.k8s.io/v1",  
        "kind": "AdmissionReview", 
        "response": 
        {"uid": request_json["request"]["uid"], "allowed": True}})

if __name__ == '__main__':
    initialize_webhook_tls()
    app.run(debug=False, host='0.0.0.0', port='5050', ssl_context=('mutate-affinity-service.crt', 'mutate-affinity-service.key'))
