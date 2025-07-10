import os
import hashlib
import magic
import zipfile
import tarfile
import tempfile
from typing import Dict, Any, List
import pdfplumber
from docx import Document
from PIL import Image
import logging

logger = logging.getLogger(__name__)

class FileProcessor:
    """Handles file processing and metadata extraction"""
    
    def __init__(self):
        self.supported_archives = ['.zip', '.rar', '.7z', '.tar', '.gz']
        self.supported_documents = ['.pdf', '.docx', '.doc', '.txt']
        self.supported_images = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg']
        self.executable_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.msi']
    
    async def process_file(self, file_path: str) -> Dict[str, Any]:
        """Process uploaded file and extract metadata"""
        try:
            file_info = {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'file_extension': os.path.splitext(file_path)[1].lower(),
                'is_executable': False,
                'is_archive': False,
                'is_document': False,
                'is_image': False,
                'mime_type': None,
                'file_hash': None,
                'metadata': {},
                'extracted_strings': [],
                'suspicious_indicators': []
            }
            
            # Calculate file hash
            file_info['file_hash'] = await self._calculate_file_hash(file_path)
            
            # Detect MIME type
            file_info['mime_type'] = magic.from_file(file_path, mime=True)
            
            # Classify file type
            file_info.update(self._classify_file_type(file_info['file_extension']))
            
            # Extract metadata based on file type
            if file_info['is_executable']:
                file_info['metadata'] = await self._process_executable(file_path)
            elif file_info['is_archive']:
                file_info['metadata'] = await self._process_archive(file_path)
            elif file_info['is_document']:
                file_info['metadata'] = await self._process_document(file_path)
            elif file_info['is_image']:
                file_info['metadata'] = await self._process_image(file_path)
            
            # Extract strings for analysis
            file_info['extracted_strings'] = await self._extract_strings(file_path)
            
            # Detect suspicious indicators
            file_info['suspicious_indicators'] = await self._detect_suspicious_indicators(file_info)
            
            return file_info
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")
            return {
                'error': str(e),
                'file_path': file_path,
                'processed': False
            }
    
    async def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _classify_file_type(self, extension: str) -> Dict[str, bool]:
        """Classify file based on extension"""
        return {
            'is_executable': extension in self.executable_extensions,
            'is_archive': extension in self.supported_archives,
            'is_document': extension in self.supported_documents,
            'is_image': extension in self.supported_images
        }
    
    async def _process_executable(self, file_path: str) -> Dict[str, Any]:
        """Process executable files"""
        metadata = {
            'type': 'executable',
            'size': os.path.getsize(file_path),
            'risk_level': 'HIGH'  # Executables are inherently risky
        }
        
        try:
            # Try to extract basic PE information (simplified)
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                if b'MZ' in header[:2]:  # DOS header
                    metadata['format'] = 'PE'
                    metadata['has_dos_header'] = True
                
                # Look for suspicious strings in header
                suspicious_strings = [b'cmd.exe', b'powershell', b'rundll32', b'regsvr32']
                for sus_str in suspicious_strings:
                    if sus_str in header:
                        metadata['suspicious_strings_found'] = True
                        break
                        
        except Exception as e:
            metadata['processing_error'] = str(e)
        
        return metadata
    
    async def _process_archive(self, file_path: str) -> Dict[str, Any]:
        """Process archive files"""
        metadata = {
            'type': 'archive',
            'files': [],
            'total_files': 0,
            'compressed_size': os.path.getsize(file_path),
            'has_executables': False,
            'suspicious_files': []
        }
        
        try:
            if file_path.lower().endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_file:
                    file_list = zip_file.namelist()
                    metadata['total_files'] = len(file_list)
                    
                    for file_name in file_list:
                        file_ext = os.path.splitext(file_name)[1].lower()
                        metadata['files'].append({
                            'name': file_name,
                            'extension': file_ext
                        })
                        
                        # Check for executables
                        if file_ext in self.executable_extensions:
                            metadata['has_executables'] = True
                            metadata['suspicious_files'].append(file_name)
                        
                        # Check for suspicious filenames
                        suspicious_names = ['virus', 'malware', 'trojan', 'backdoor', 'payload']
                        if any(sus_name in file_name.lower() for sus_name in suspicious_names):
                            metadata['suspicious_files'].append(file_name)
                            
        except Exception as e:
            metadata['processing_error'] = str(e)
        
        return metadata
    
    async def _process_document(self, file_path: str) -> Dict[str, Any]:
        """Process document files"""
        metadata = {
            'type': 'document',
            'text_content': '',
            'has_macros': False,
            'has_external_links': False,
            'suspicious_content': []
        }
        
        try:
            if file_path.lower().endswith('.pdf'):
                with pdfplumber.open(file_path) as pdf:
                    metadata['pages'] = len(pdf.pages)
                    text_content = ''
                    for page in pdf.pages:
                        page_text = page.extract_text()
                        if page_text:
                            text_content += page_text + '\n'
                    metadata['text_content'] = text_content[:1000]  # Limit size
                    
            elif file_path.lower().endswith(('.docx', '.doc')):
                # For .docx files
                if file_path.lower().endswith('.docx'):
                    doc = Document(file_path)
                    text_content = ''
                    for paragraph in doc.paragraphs:
                        text_content += paragraph.text + '\n'
                    metadata['text_content'] = text_content[:1000]  # Limit size
                    
                    # Check for macros (simplified check)
                    # In a real implementation, you'd need to check for VBA macros
                    if 'macro' in text_content.lower() or 'vba' in text_content.lower():
                        metadata['has_macros'] = True
            
            # Check for suspicious content
            suspicious_keywords = [
                'click here', 'urgent', 'verify account', 'suspended', 'download now',
                'winner', 'congratulations', 'free money', 'nigerian prince'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in metadata['text_content'].lower():
                    metadata['suspicious_content'].append(keyword)
                    
        except Exception as e:
            metadata['processing_error'] = str(e)
        
        return metadata
    
    async def _process_image(self, file_path: str) -> Dict[str, Any]:
        """Process image files"""
        metadata = {
            'type': 'image',
            'format': None,
            'dimensions': None,
            'has_exif': False,
            'exif_data': {}
        }
        
        try:
            with Image.open(file_path) as img:
                metadata['format'] = img.format
                metadata['dimensions'] = img.size
                metadata['mode'] = img.mode
                
                # Extract EXIF data if available
                if hasattr(img, '_getexif') and img._getexif():
                    metadata['has_exif'] = True
                    # In a real implementation, you'd want to parse specific EXIF fields
                    metadata['exif_data'] = {'has_metadata': True}
                    
        except Exception as e:
            metadata['processing_error'] = str(e)
        
        return metadata
    
    async def _extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract readable strings from file"""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                current_string = ""
                
                for byte in data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string += chr(byte)
                    else:
                        if len(current_string) >= min_length:
                            strings.append(current_string)
                        current_string = ""
                
                # Don't return too many strings to avoid memory issues
                return strings[:100]
                
        except Exception as e:
            logger.error(f"Error extracting strings from {file_path}: {str(e)}")
            return []
    
    async def _detect_suspicious_indicators(self, file_info: Dict[str, Any]) -> List[str]:
        """Detect suspicious indicators in file"""
        indicators = []
        
        # Check file size (very small or very large files can be suspicious)
        file_size = file_info.get('file_size', 0)
        if file_size < 100:  # Very small files
            indicators.append("unusually_small_file")
        elif file_size > 100 * 1024 * 1024:  # Very large files
            indicators.append("unusually_large_file")
        
        # Check extension mismatches
        extension = file_info.get('file_extension', '')
        mime_type = file_info.get('mime_type', '')
        if extension == '.jpg' and 'image' not in mime_type:
            indicators.append("extension_mime_mismatch")
        
        # Check for executable disguised as other file types
        if file_info.get('is_executable') and extension not in self.executable_extensions:
            indicators.append("disguised_executable")
        
        # Check extracted strings for suspicious content
        strings = file_info.get('extracted_strings', [])
        suspicious_strings = [
            'cmd.exe', 'powershell', 'rundll32', 'regsvr32',
            'bitcoin', 'cryptocurrency', 'wallet.dat',
            'keylogger', 'password', 'credential'
        ]
        
        for string in strings:
            for sus_string in suspicious_strings:
                if sus_string.lower() in string.lower():
                    indicators.append(f"suspicious_string_{sus_string}")
                    break
        
        return indicators