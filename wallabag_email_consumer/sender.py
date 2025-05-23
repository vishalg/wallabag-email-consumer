import smtplib
from email.encoders import encode_base64
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

from logbook import Logger

logger = Logger(__name__)


class Sender:
    def __init__(self, loop, from_addr, smtp_server, smtp_port, smtp_user=None, smtp_passwd=None):
        self.from_addr = from_addr
        self.loop = loop
        self.host = smtp_server
        self.port = smtp_port
        self.user = smtp_user
        self.passwd = smtp_passwd

    def _send_mail(self, title, article, attachment_format, email_addresses, data):
        msg = MIMEMultipart()
        msg["Subject"] = "Send article {}".format(article)
        msg["From"] = self.from_addr
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid("wallabag-email")

        text = "This email has been automatically sent."
        msg.attach(MIMEText(text))

        mobi = MIMEApplication(data)
        encode_base64(mobi)
        mobi.add_header(
            "Content-Disposition",
            "attachment",
            filename="{title}.{format}".format(title=title, format=attachment_format),
        )

        msg.attach(mobi)

        smtp = smtplib.SMTP(host=self.host, port=self.port)
        smtp.starttls()
        if self.user is not None:
            smtp.login(self.user, self.passwd)

        msg["To"] = email_addresses
        smtp.sendmail(self.from_addr, [email.strip() for email in email_addresses.split(",")], msg.as_string())
        logger.info(
            "Mail with article {article} in format {format} with title {title} sent to {email}".format(
                article=article, title=title, format=attachment_format, email=email_addresses
            )
        )

        smtp.quit()

    async def send_mail(self, job, data):
        return self.loop.run_in_executor(
            None, self._send_mail, job.title, job.article, job.format, job.user.send_to_emails, data
        )

    def _send_warning(self, email, config):
        msg = MIMEMultipart()
        msg["Subject"] = "Wallabag-Email-Consumer Notice"
        msg["From"] = self.from_addr
        msg["To"] = email
        msg["Date"] = formatdate(localtime=True)

        txt = MIMEText(
            (
                "the Wallabag-Email-Consumer for your Wallabag "
                "account on {wallabag} was not able to refresh "
                "the access token. Please go to {url}/update and log "
                "in again to retrieve a new api token."
            ).format(wallabag=config.wallabag_host, url=config.domain)
        )

        msg.attach(txt)

        smtp = smtplib.SMTP(host=self.host, port=self.port)
        smtp.starttls()
        if self.user is not None:
            smtp.login(self.user, self.passwd)
        smtp.sendmail(self.from_addr, [email], msg.as_string())
        smtp.quit()
        logger.info("Notify mail sent to {user}", user=email)

    async def send_warning(self, user, config):
        return self.loop.run_in_executor(None, self._send_warning, user.email, config)
