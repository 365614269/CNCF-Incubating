# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
Azure Queue Message Processing
==============================

"""
import base64
import json
import zlib

from c7n_mailer.azure_mailer.sendgrid_delivery import SendGridDelivery
from c7n_mailer.smtp_delivery import SmtpDelivery
from c7n_mailer.target import MessageTargetMixin

try:
    from c7n_azure.storage_utils import StorageUtilities
    from c7n_azure.session import Session
except ImportError:
    raise ImportError(
        "c7n-mailer is configured for Azure Queues, which requires additional packages. "
        "Run 'pip install c7n-mailer[azure]' to install them."
    )


class MailerAzureQueueProcessor(MessageTargetMixin):
    def __init__(self, config, logger, session=None, max_num_processes=16):
        self.max_num_processes = max_num_processes
        self.config = config
        self.logger = logger
        self.receive_queue = self.config["queue_url"]
        self.batch_size = 16
        self.max_message_retry = 3
        self.session = session or Session()

    def run(self, parallel=False):
        if parallel:
            self.logger.info("Parallel processing with Azure Queue is not yet implemented.")

        self.logger.info("Downloading messages from the Azure Storage queue.")
        queue_settings = StorageUtilities.get_queue_client_by_uri(self.receive_queue, self.session)
        queue_messages = StorageUtilities.get_queue_messages(
            *queue_settings, num_messages=self.batch_size
        )

        while len(queue_messages) > 0:
            for queue_message in queue_messages:
                self.logger.debug("Message id: %s received" % queue_message.id)

                if (
                    self.process_azure_queue_message(queue_message, str(queue_message.inserted_on))
                    or queue_message.dequeue_count > self.max_message_retry
                ):
                    # If message handled successfully or max retry hit, delete
                    StorageUtilities.delete_queue_message(*queue_settings, message=queue_message)

            queue_messages = StorageUtilities.get_queue_messages(
                *queue_settings, num_messages=self.batch_size
            )

        self.logger.info("No messages left on the azure storage queue, exiting c7n_mailer.")

    def process_azure_queue_message(self, encoded_azure_queue_message, timestamp):
        queue_message = json.loads(
            zlib.decompress(base64.b64decode(encoded_azure_queue_message.content))
        )

        self.logger.debug(
            "Got account:%s message:%s %s:%d policy:%s recipients:%s"
            % (
                queue_message.get("account", "na"),
                encoded_azure_queue_message.id,
                queue_message["policy"]["resource"],
                len(queue_message["resources"]),
                queue_message["policy"]["name"],
                ", ".join(queue_message["action"].get("to", [])),
            )
        )

        self.handle_targets(queue_message, timestamp, email_delivery=False, sns_delivery=False)

        email_result = self._deliver_email(queue_message)

        if email_result is not None:
            return email_result
        else:
            return True

    def _deliver_email(self, queue_message):
        try:
            sendgrid_delivery = SendGridDelivery(self.config, self.session, self.logger)
            email_messages = sendgrid_delivery.get_to_addrs_sendgrid_messages_map(queue_message)

            if "smtp_server" in self.config:
                smtp_delivery = SmtpDelivery(
                    config=self.config, session=self.session, logger=self.logger
                )
                for to_addrs, message in email_messages.items():
                    self.logger.info(
                        "Sending message to SMTP server, {}.".format(self.config["smtp_server"])
                    )
                    smtp_delivery.send_message(message=message, to_addrs=list(to_addrs))
            else:
                self.logger.info("Sending message to Sendgrid.")
                return sendgrid_delivery.sendgrid_handler(queue_message, email_messages)
        except Exception as error:
            self.logger.exception(error)
