Instructions for installing the mutating affinity injector.

CAST AI Namespace must exist, and cluster should be in Phase 2 already

1. Apply service_account.yaml
2. You can use the docker image referenced in the deployment yaml
3. Apply mutate_affinity_configuration.yaml
4. Apply mutate_affinity_deployment.yaml

You should see the mutate-affinity pod show up in the castai-agent namespace. Check the logs, the server should be UP.

You can then apply: test_nginx.yaml and the nginx pod should be mutated to include arm/amd node affinity.