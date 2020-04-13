from typing import Dict, Tuple, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend

class TLSContext:
	def __init__(self, cert_root: str, cert_dir: str) -> None:
		self.cert_dir = Path(cert_dir)
		self.cert_root = cert_root
		self._cert_cache = {} # type: Dict[str, ssl.SSLContext]
	
	def create_ssl_context(self) -> ssl.SSLContext:
		self._get_root_cert()
		
		ssl_context = ssl.create_default_context(purpose = ssl.Purpose.CLIENT_AUTH)
		
		cache = self._cert_cache
		def servername_callback(socket: Any, domain: Optional[str], ssl_context: ssl.SSLSocket) -> Optional[int]:
			if domain is None:
				domain = 'no-domain'
			if domain not in cache:
				ctxt = ssl.create_default_context(purpose = ssl.Purpose.CLIENT_AUTH)
				p_crt, p_key = self._get_cert(domain)
				ctxt.load_cert_chain(str(p_crt), keyfile = str(p_key))
				cache[domain] = ctxt
			socket.context = cache[domain]
			return None
		
		ssl_context.set_servername_callback(servername_callback)
		return ssl_context
	
	def _get_cert(self, domain: str) -> Tuple[Path, Path]:
		p_crt = self.cert_dir / '{}.crt'.format(domain)
		p_key = self.cert_dir / '{}.key'.format(domain)
		
		if not exists_and_valid(p_crt, p_key):
			raise ssl.CertificateError()
		
		return p_crt, p_key
	
	def _get_root_cert(self) -> Tuple[Path, Path]:
		assert self.cert_root is not None
		
		p_crt = self.cert_dir / '{}.crt'.format(self.cert_root)
		p_key = self.cert_dir / '{}.key'.format(self.cert_root)
		
		if not exists_and_valid(p_crt, p_key):
			raise ssl.CertificateError()
		
		return p_crt, p_key

def exists_and_valid(p_crt: Path, p_key: Path) -> bool:
	if not p_crt.exists(): return False
	if not p_key.exists(): return False
	backend = default_backend()
	with p_crt.open('rb') as fh:
		crt = x509.load_pem_x509_certificate(fh.read(), backend)
	
	now = datetime.utcnow()
	if now < crt.not_valid_before: return False
	near_future = now + timedelta(days = 1)
	if near_future > crt.not_valid_after: return False
	return True
