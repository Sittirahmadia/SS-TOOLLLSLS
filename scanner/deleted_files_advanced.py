"""
Advanced Deleted Files Recovery Scanner v2.0
File system deep analysis for recovery and forensics
"""

import os
import sys
import struct
import json
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class DeletedFilesScanner:
    """Advanced deleted file detection and recovery"""
    
    # File signatures for carving
    FILE_SIGNATURES = {
        'pdf': b'%PDF',
        'jpeg': b'\xff\xd8\xff',
        'png': b'\x89PNG\r\n\x1a\n',
        'gif': b'GIF8',
        'zip': b'PK\x03\x04',
        'docx': b'PK\x03\x04',
        'xlsx': b'PK\x03\x04',
        'exe': b'MZ',
        'dll': b'MZ',
        'bmp': b'BM',
        'avi': b'RIFF',
        'mp4': b'\x00\x00\x00\x18ftypmp42',
        'mp3': b'\xff\xfb',
    }
    
    FILE_EXTENSIONS = {
        'pdf': ['.pdf'],
        'jpeg': ['.jpg', '.jpeg'],
        'png': ['.png'],
        'gif': ['.gif'],
        'zip': ['.zip'],
        'docx': ['.docx', '.xlsx'],
        'exe': ['.exe', '.sys'],
        'dll': ['.dll'],
    }
    
    def __init__(self):
        self.found_files = []
        self.system = sys.platform
    
    def scan_directory(self, path: str, max_depth: int = 3) -> dict:
        """Scan directory for deleted file traces"""
        result = {
            'total_files': 0,
            'deleted_candidates': [],
            'recovery_possible': 0,
            'risk_level': 'CLEAN',
            'summary': {}
        }
        
        try:
            for root, dirs, files in os.walk(path):
                # Limit depth
                depth = root.count(os.sep) - path.count(os.sep)
                if depth > max_depth:
                    dirs[:] = []
                    continue
                
                result['total_files'] += len(files)
                
                # Scan files for suspicious patterns
                for file in files[:100]:  # Limit files for speed
                    full_path = os.path.join(root, file)
                    try:
                        file_result = self._analyze_file(full_path)
                        if file_result['suspicious']:
                            result['deleted_candidates'].append(file_result)
                            result['recovery_possible'] += 1
                    except:
                        pass
            
            if result['deleted_candidates']:
                result['risk_level'] = 'HIGH - Deleted Files Found'
            
            result['summary'] = self._generate_summary(result['deleted_candidates'])
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _analyze_file(self, file_path: str) -> dict:
        """Analyze individual file for deletion signatures"""
        result = {
            'file': os.path.basename(file_path),
            'path': file_path,
            'suspicious': False,
            'indicators': [],
            'recovery_score': 0,
            'type': 'unknown'
        }
        
        try:
            stat = os.stat(file_path)
            
            # Check for suspicious patterns
            indicators = []
            
            # Hidden files
            if os.name == 'nt' and os.path.isfile(file_path):
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                if attrs & 2:  # Hidden attribute
                    indicators.append('hidden_file')
                    result['recovery_score'] += 15
            
            # Recently modified (deletion time close to access)
            mtime = stat.st_mtime
            atime = stat.st_atime
            time_diff = abs(mtime - atime)
            
            if time_diff < 3600:  # Less than 1 hour
                indicators.append('recent_modification')
                result['recovery_score'] += 20
            
            # Zero size or very small files
            if stat.st_size == 0:
                indicators.append('zero_size')
                result['recovery_score'] += 25
            elif stat.st_size < 512:
                indicators.append('very_small')
                result['recovery_score'] += 10
            
            # Check file permissions
            if not os.access(file_path, os.R_OK):
                indicators.append('unreadable')
                result['recovery_score'] += 20
            
            # Detect file type by signature
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(512)
                
                for file_type, sig in self.FILE_SIGNATURES.items():
                    if header.startswith(sig):
                        result['type'] = file_type
                        result['recovery_score'] += 30
                        indicators.append(f'signature_match:{file_type}')
                        break
            except:
                pass
            
            # Check filename for suspicious patterns
            filename_lower = os.path.basename(file_path).lower()
            
            suspicious_patterns = [
                'temp', 'tmp', 'cache', 'recycle', 'trash',
                '$RECYCLE.BIN', 'System Volume Information',
                'thumbs.db', 'desktop.ini'
            ]
            
            if any(pattern in filename_lower for pattern in suspicious_patterns):
                indicators.append('suspicious_location')
                result['recovery_score'] += 15
            
            result['indicators'] = indicators
            result['suspicious'] = len(indicators) > 0
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _generate_summary(self, candidates: list) -> dict:
        """Generate summary statistics"""
        summary = {
            'by_type': {},
            'by_indicator': {},
            'recovery_stats': {
                'excellent': 0,  # > 80
                'good': 0,       # 60-80
                'fair': 0,       # 40-60
                'poor': 0        # < 40
            }
        }
        
        for candidate in candidates:
            # Type summary
            ftype = candidate['type']
            summary['by_type'][ftype] = summary['by_type'].get(ftype, 0) + 1
            
            # Indicators
            for indicator in candidate['indicators']:
                summary['by_indicator'][indicator] = summary['by_indicator'].get(indicator, 0) + 1
            
            # Recovery score distribution
            score = candidate['recovery_score']
            if score > 80:
                summary['recovery_stats']['excellent'] += 1
            elif score > 60:
                summary['recovery_stats']['good'] += 1
            elif score > 40:
                summary['recovery_stats']['fair'] += 1
            else:
                summary['recovery_stats']['poor'] += 1
        
        return summary
    
    def scan_system(self) -> dict:
        """Full system scan for deleted files"""
        result = {
            'windows': None,
            'users': None,
            'temp': None,
            'total_deleted': 0,
            'risk_level': 'CLEAN',
            'summary': {}
        }
        
        try:
            if sys.platform == 'win32':
                # Windows temp
                temp_path = os.environ.get('TEMP', 'C:\\Windows\\Temp')
                result['temp'] = self.scan_directory(temp_path)
                result['total_deleted'] += result['temp'].get('recovery_possible', 0)
                
                # Windows directory
                win_path = 'C:\\Windows'
                if os.path.exists(win_path):
                    result['windows'] = self.scan_directory(win_path, max_depth=2)
                    result['total_deleted'] += result['windows'].get('recovery_possible', 0)
                
                # User directories
                users_path = os.environ.get('USERPROFILE', 'C:\\Users')
                if os.path.exists(users_path):
                    result['users'] = self.scan_directory(users_path, max_depth=2)
                    result['total_deleted'] += result['users'].get('recovery_possible', 0)
            
            else:  # Linux/Mac
                # Temp directory
                result['temp'] = self.scan_directory('/tmp')
                result['total_deleted'] += result['temp'].get('recovery_possible', 0)
                
                # Home directory
                home = os.path.expanduser('~')
                result['users'] = self.scan_directory(home, max_depth=2)
                result['total_deleted'] += result['users'].get('recovery_possible', 0)
            
            if result['total_deleted'] > 0:
                result['risk_level'] = 'MEDIUM - Deleted Files Detected'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result

if __name__ == '__main__':
    import json
    
    scanner = DeletedFilesScanner()
    
    if len(sys.argv) > 1:
        path = sys.argv[1]
        result = scanner.scan_directory(path)
    else:
        result = scanner.scan_system()
    
    print(json.dumps(result, indent=2, default=str))
