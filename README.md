# Secure Notes Manager

This project implements a secure note management system in Python. It provides features for adding, retrieving, and deleting notes, with encryption, rollback protection, and serialization to safeguard sensitive information.

## Features

- **Encryption**: Notes are encrypted using AES-GCM for confidentiality.
- **Rollback Protection**: Prevents loading old versions of notes using checksums.
- **Serialization**: Allows for saving and loading notes securely.
- **Note Management**: Add, retrieve, update, and delete notes easily.