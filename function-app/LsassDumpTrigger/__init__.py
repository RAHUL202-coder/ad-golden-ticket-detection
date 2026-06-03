import azure.functions as func
import json
import logging

def main(myblob: func.InputStream, sbMessage: func.Out[str]) -> None:
    blob_name = myblob.name
    blob_size = myblob.length
    logging.info(f"LSASS dump detected: {blob_name} ({blob_size} bytes)")

    message = json.dumps({
        "blobName": blob_name,
        "storageAccount": "memorydumps202605121306",
        "container": "artifacts",
        "sizeBytes": blob_size,
        "triggerSource": "LsassDumpTrigger"
    })

    sbMessage.set(message)
    logging.info(f"Queued for Volatility analysis: {blob_name}")
