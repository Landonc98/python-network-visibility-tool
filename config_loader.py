import yaml
import os

def load_config(file_path="config.yaml"):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Config file not found: {file_path}")
    with open(file_path, 'r') as file:
        try:
            config = yaml.safe_load(file)
            validate_config(config)
            return config
        except yaml.YAMLError as e:
            raise Exception(f"YAML parsing error: {e}")

def validate_config(config):
    required_keys = ['targets', 'ports', 'output_dir']
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

