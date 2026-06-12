"""
BadZure - Automated Azure Attack Path Deployment Tool

A Python tool that utilizes Terraform to automate the setup of Entra ID tenants
and Azure subscriptions, populating them with various entities and introducing common
security misconfigurations to create vulnerable tenants with multiple attack paths.

Author: Mauricio Velazco (@mvelazco)
"""
import os
import click
import logging
import time

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip loading .env file

from src.cli import BuildCommand, ShowCommand, DestroyCommand, GenerateCommand

# Ensure AZURE_CONFIG_DIR is set to the Azure CLI config directory
os.environ['AZURE_CONFIG_DIR'] = os.path.expanduser('~/.azure')

banner = r"""

            ____            _ ______
            |  _ \          | |___  /
            | |_) | __ _  __| |  / /_   _ _ __ ___
            |  _ < / _` |/ _` | / /| | | | '__/ _ \
            | |_) | (_| | (_| |/ /_| |_| | | |  __/
            |____/ \__,_|\__,_/_____\__,_|_|  \___|
                                                    
                                                                                                                                    
                                by Mauricio Velazco
                                @mvelazco

"""


def setup_logging(level=logging.INFO):
    """Setup custom logging format."""
    custom_formats = {
        logging.INFO: "{timestamp}[+] %(message)s",
        logging.ERROR: "{timestamp}[!] %(message)s",
        "DEFAULT": "{timestamp}[%(levelname)s] - %(message)s",
    }
    custom_time_format = "%Y-%m-%d %H:%M:%S"
    
    class CustomFormatter(logging.Formatter):
        def __init__(self, fmt=None, datefmt=None, style='%'):
            super().__init__(fmt, datefmt=custom_time_format, style=style)
        
        def format(self, record):
            if hasattr(record, 'include_timestamp') and not record.include_timestamp:
                timestamp = ""
            else:
                timestamp = f"{self.formatTime(record, self.datefmt)} "
            
            self._style._fmt = custom_formats.get(
                record.levelno, custom_formats["DEFAULT"]
            ).format(timestamp=timestamp)
            return super().format(record)
    
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomFormatter())
    root_logger.addHandler(console_handler)
    root_logger.setLevel(level)


@click.group()
def cli():
    """BadZure - Automated Azure Attack Path Deployment Tool"""
    pass


@cli.command()
@click.option('--config', type=click.Path(exists=True), default='badzure.yml',
              help="Path to the configuration YAML file")
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def build(config, verbose):
    """Create resources and attack paths"""
    command = BuildCommand()
    command.execute(config, verbose)


@cli.command()
@click.option('--prompt', help="Natural-language description of the org to generate (baseline)")
@click.option('--attack-prompt', 'attack_prompt',
              help="(later slice) Description of attack paths to generate")
@click.option('--input', 'input_config', type=click.Path(exists=True),
              help="(later slice) Existing config to extend with generated attack paths")
@click.option('-o', '--output', default='generated.yml',
              help="Where to write the generated config (default: generated.yml)")
@click.option('--model', help="LLM model (e.g. anthropic/claude-opus-4-1, openai/gpt-4o); "
                              "overrides BADZURE_LLM_MODEL / llm.model")
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def generate(prompt, attack_prompt, input_config, output, model, verbose):
    """Generate a declarative config from a prompt using an LLM (review, then build)"""
    command = GenerateCommand()
    command.execute(prompt=prompt, attack_prompt=attack_prompt,
                    input_config=input_config, output=output, model=model, verbose=verbose)


@cli.command()
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def show(verbose):
    """Show all the created resources in the tenant"""
    command = ShowCommand()
    command.execute(verbose)


@cli.command()
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def destroy(verbose):
    """Destroy all created resources in the tenant"""
    command = DestroyCommand()
    command.execute(verbose)


if __name__ == '__main__':
    setup_logging(logging.INFO)
    print(banner)
    time.sleep(2)
    cli()
