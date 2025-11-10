import subprocess
import shutil
import json
from typing import Dict, Any, Optional, List
from pathlib import Path


class TSharkExecutor:
    def __init__(self):
        self.tshark_path = self._find_tshark()
        self.max_output_size = 1000000  # 1MB max output
        self.command_timeout = 60  # 60 seconds timeout

    def _find_tshark(self) -> Optional[str]:
        tshark_path = shutil.which('tshark')
        if tshark_path:
            return tshark_path

        common_paths = [
            '/usr/bin/tshark',
            '/usr/local/bin/tshark',
            'C:\\Program Files\\Wireshark\\tshark.exe',
            '/Applications/Wireshark.app/Contents/MacOS/tshark'
        ]

        for path in common_paths:
            if Path(path).exists():
                return path

        return None

    def is_available(self) -> bool:
        return self.tshark_path is not None

    def get_installation_instructions(self) -> str:
        return """TShark is not installed. Please install it:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tshark
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download and install Wireshark from https://www.wireshark.org/download.html

After installation, restart the application."""

    def validate_command(self, command_parts: List[str]) -> Dict[str, Any]:
        if not command_parts:
            return {
                'valid': False,
                'error': 'Empty command provided'
            }

        dangerous_flags = [
            '-w',  # Write output file
            '-F',  # File format
            '-i',  # Interface (live capture)
            '-k',  # Start capture immediately
            '-b',  # Ring buffer
            '-a',  # Autostop
        ]

        for flag in dangerous_flags:
            if flag in command_parts:
                return {
                    'valid': False,
                    'error': f'Dangerous flag "{flag}" is not allowed. Only read operations on PCAP files are permitted.'
                }

        # Check for duplicate -r flags
        r_flag_count = sum(1 for part in command_parts if part == '-r')
        if r_flag_count > 1:
            return {
                'valid': False,
                'error': 'Duplicate -r flags detected. Command should only have one -r flag.'
            }

        if not any('-r' in part for part in command_parts):
            return {
                'valid': False,
                'error': 'Command must include -r flag to read from a PCAP file'
            }

        return {'valid': True}

    def execute_tshark_command(
        self,
        pcap_file_path: str,
        display_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
        output_format: str = 'text',
        read_filter: Optional[str] = None,
        additional_args: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        if not self.is_available():
            return {
                'success': False,
                'error': 'TShark is not installed',
                'error_type': 'not_installed',
                'installation_instructions': self.get_installation_instructions()
            }

        if not Path(pcap_file_path).exists():
            return {
                'success': False,
                'error': f'PCAP file not found: {pcap_file_path}',
                'error_type': 'file_not_found'
            }

        command = [self.tshark_path, '-r', pcap_file_path]

        if display_filter:
            command.extend(['-Y', display_filter])

        if read_filter:
            command.extend(['-R', read_filter])

        if output_format == 'json':
            command.extend(['-T', 'json'])
        elif output_format == 'fields' and fields:
            command.extend(['-T', 'fields'])
            for field in fields:
                command.extend(['-e', field])
        elif output_format == 'text':
            pass  # Default output

        if additional_args:
            command.extend(additional_args)

        validation = self.validate_command(command)
        if not validation['valid']:
            return {
                'success': False,
                'error': validation['error'],
                'error_type': 'invalid_command'
            }

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.command_timeout,
                check=False
            )

            if result.returncode != 0:
                return {
                    'success': False,
                    'error': f'TShark command failed: {result.stderr}',
                    'error_type': 'execution_error',
                    'stderr': result.stderr,
                    'command': ' '.join(command)
                }

            output = result.stdout

            if len(output) > self.max_output_size:
                output = output[:self.max_output_size]
                truncated = True
            else:
                truncated = False

            parsed_output = output
            if output_format == 'json' and output.strip():
                try:
                    parsed_output = json.loads(output)
                except json.JSONDecodeError:
                    pass  # Keep as text if JSON parsing fails

            return {
                'success': True,
                'output': parsed_output,
                'raw_output': output,
                'truncated': truncated,
                'command': ' '.join(command),
                'output_format': output_format
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Command timed out after {self.command_timeout} seconds',
                'error_type': 'timeout',
                'command': ' '.join(command)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'error_type': 'unknown',
                'command': ' '.join(command)
            }

    def _clean_command_args(self, args: List[str]) -> List[str]:
        """Remove duplicate -r flags and file paths from command arguments."""
        cleaned = []
        skip_next = False

        for i, arg in enumerate(args):
            if skip_next:
                skip_next = False
                continue

            # Skip -r flags and their associated file paths
            if arg == '-r':
                # Skip this flag and the next argument (which is the file path)
                skip_next = True
                continue

            # Skip arguments that look like file paths
            if arg.endswith('.pcap') or arg.endswith('.pcapng') or arg.endswith('.cap'):
                continue

            # Skip if it's a path to file.pcap or contains file path patterns
            if 'file.pcap' in arg or '/' in arg or '\\' in arg:
                continue

            cleaned.append(arg)

        return cleaned

    def execute_custom_command(
        self,
        pcap_file_path: str,
        tshark_args: List[str]
    ) -> Dict[str, Any]:
        if not self.is_available():
            return {
                'success': False,
                'error': 'TShark is not installed',
                'error_type': 'not_installed',
                'installation_instructions': self.get_installation_instructions()
            }

        if not Path(pcap_file_path).exists():
            return {
                'success': False,
                'error': f'PCAP file not found: {pcap_file_path}',
                'error_type': 'file_not_found'
            }

        # Clean the arguments to remove duplicate -r flags and file paths
        cleaned_args = self._clean_command_args(tshark_args)

        command = [self.tshark_path, '-r', pcap_file_path] + cleaned_args

        validation = self.validate_command(command)
        if not validation['valid']:
            return {
                'success': False,
                'error': validation['error'],
                'error_type': 'invalid_command'
            }

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.command_timeout,
                check=False
            )

            if result.returncode != 0:
                return {
                    'success': False,
                    'error': f'TShark command failed: {result.stderr}',
                    'error_type': 'execution_error',
                    'stderr': result.stderr,
                    'command': ' '.join(command)
                }

            output = result.stdout

            if len(output) > self.max_output_size:
                output = output[:self.max_output_size]
                truncated = True
            else:
                truncated = False

            return {
                'success': True,
                'output': output,
                'raw_output': output,
                'truncated': truncated,
                'command': ' '.join(command)
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Command timed out after {self.command_timeout} seconds',
                'error_type': 'timeout',
                'command': ' '.join(command)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'error_type': 'unknown',
                'command': ' '.join(command)
            }

    def get_packet_count(self, pcap_file_path: str) -> Dict[str, Any]:
        return self.execute_custom_command(pcap_file_path, ['-q', '-z', 'io,stat,0'])

    def get_protocol_hierarchy(self, pcap_file_path: str) -> Dict[str, Any]:
        return self.execute_custom_command(pcap_file_path, ['-q', '-z', 'io,phs'])

    def filter_by_ip(self, pcap_file_path: str, ip_address: str) -> Dict[str, Any]:
        return self.execute_tshark_command(
            pcap_file_path,
            display_filter=f'ip.addr == {ip_address}'
        )

    def filter_by_protocol(self, pcap_file_path: str, protocol: str) -> Dict[str, Any]:
        return self.execute_tshark_command(
            pcap_file_path,
            display_filter=protocol.lower()
        )
