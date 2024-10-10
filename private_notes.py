import os
import hashlib
import pickle
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class PrivNotes:
  MAX_NOTE_LEN = 2048;

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    if data is not None:
      raw_data = bytes.fromhex(data)
      calculated_checksum = hashlib.sha256(raw_data).hexdigest()

      if checksum is not None and checksum != calculated_checksum:
        raise ValueError("checksum validation failed or missing")

      try:
        with open('trusted_hash.txt', 'r') as f:
          trusted_checksum = f.read().strip()
      except FileNotFoundError:
        raise ValueError("trusted hash file not found")

      if trusted_checksum != calculated_checksum:
        raise ValueError("rollback protection checksum validation failed")

      try:
        deserialized_data = pickle.loads(raw_data)
        self.kvs = deserialized_data['kvs']
        self.salt = deserialized_data['salt']
        self.nonce_counter = deserialized_data.get('nonce_counter', 0)
      except (pickle.UnpicklingError, ValueError, KeyError):
        raise ValueError("data deserialization failed")
      
      kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=self.salt,
        iterations=2000000
      )

      try:
        self.source_key = kdf.derive(bytes(password, 'ascii'))
      except Exception:
        raise ValueError("password validation failed")

      self.hmac_key = self._derive_key(self.source_key, b"HMAC-key")
      self.aes_key = self._derive_key(self.source_key, b"AES-key")

      if len(self.kvs) > 0:
        try:
          sample_hashed_title, encrypted_data = next(iter(self.kvs.items()))
          ciphertext = encrypted_data['ciphertext']
          nonce = encrypted_data['nonce']
          aesgcm = AESGCM(self.aes_key)
          aesgcm.decrypt(nonce, ciphertext, bytes.fromhex(sample_hashed_title))
        except InvalidTag:
          raise ValueError("password validation failed")
    
    else:
      self.salt = os.urandom(16)
      self.kvs = {}
      self.nonce_counter = 0

      kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=self.salt,
        iterations=2000000
      )

      try:
        self.source_key = kdf.derive(bytes(password, 'ascii'))
      except Exception:
        raise ValueError("password validation failed")
      
      self.hmac_key = self._derive_key(self.source_key, b"HMAC-key")
      self.aes_key = self._derive_key(self.source_key, b"AES-key")

  def _derive_key(self, key, info):
    """Derives a new key using HMAC-SHA256"""
    h = HMAC(key, SHA256())
    h.update(info)
    return h.finalize()

  def _derive_nonce(self, title_hmac, counter):
    """Derives a nonce using the title HMAC and a counter"""
    input_data = title_hmac + counter.to_bytes(8, 'big')
    h = HMAC(self.source_key, SHA256())
    h.update(input_data)
    return h.finalize()[:12]

  def _compute_title_hmac(self, title):
    """Computes an HMAC for a given title"""
    h = HMAC(self.hmac_key, SHA256())
    h.update(title.encode('ascii'))
    return h.finalize().hex()

  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    serialized_data = pickle.dumps({
        'kvs': self.kvs,
        'salt': self.salt,
        'nonce_counter': self.nonce_counter
    })

    checksum = hashlib.sha256(serialized_data).hexdigest()

    with open('trusted_hash.txt', 'w') as f:
      f.write(checksum)

    return serialized_data.hex(), checksum

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    normalized_title = title.strip().lower()
    hashed_title = self._compute_title_hmac(normalized_title)

    if hashed_title in self.kvs:
        encrypted_data = self.kvs[hashed_title]
        ciphertext = encrypted_data['ciphertext']
        nonce = encrypted_data['nonce']

        aesgcm = AESGCM(self.aes_key)
        try:
            decrypted_padded_note = aesgcm.decrypt(nonce, ciphertext, bytes.fromhex(hashed_title))
        except InvalidTag:
            print("decryption failed due to InvalidTag error")
            raise
        
        original_len = int.from_bytes(decrypted_padded_note[:4], 'big')
        note = decrypted_padded_note[4:4 + original_len]
        return note.decode('ascii')
    return None

  def set(self, title, note):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """
    normalized_title = title.strip().lower()
    note_bytes = note.encode('ascii')
    original_len = len(note_bytes)

    if original_len > self.MAX_NOTE_LEN:
        raise ValueError('maximum note length exceeded')
    
    length_bytes = original_len.to_bytes(4, 'big')
    note_with_length = length_bytes + note_bytes
    
    padding_length = self.MAX_NOTE_LEN - original_len
    padded_note = note_with_length + b'\x00' * padding_length

    hashed_title = self._compute_title_hmac(normalized_title)
    nonce = self._derive_nonce(bytes.fromhex(hashed_title), self.nonce_counter)

    aesgcm = AESGCM(self.aes_key)
    ciphertext = aesgcm.encrypt(nonce, padded_note, bytes.fromhex(hashed_title))

    self.kvs[hashed_title] = {
        'ciphertext': ciphertext,
        'nonce': nonce
    }

    self.nonce_counter += 1
    self._update_checksum()

  def _update_checksum(self):
    """Updates checksum file after any write operation"""
    _, checksum = self.dump()
    with open('trusted_hash.txt', 'w') as f:
      f.write(checksum)

  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    normalized_title = title.strip().lower()
    hashed_title = self._compute_title_hmac(normalized_title)

    if hashed_title in self.kvs:
        del self.kvs[hashed_title]
        self._update_checksum()
        return True
    return False