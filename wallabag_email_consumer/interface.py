import asyncio
import os

import aiohttp_jinja2
import jinja2
from aiohttp import web

from logbook import Logger
from email_validator import validate_email, EmailNotValidError

from . import wallabag
from . import models

logger = Logger(__name__)


class Validator:
    def __init__(self, loop, config, data):
        self.loop = loop
        self.data = data
        self.config = config
        self.errors = {}
        self.username = None
        self.password = None
        self.send_to_emails = None
        self.notify_email = None

    async def validate_credentials(self):
        errors = {}
        if "username" not in self.data or 0 == len(self.data["username"]):
            errors["username"] = "Username not given or empty"
        else:
            self.username = self.data["username"]

        if "password" not in self.data or 0 == len(self.data["password"]):
            errors["password"] = "Password not given or empty"
        else:
            self.password = self.data["password"]

        self.errors.update(errors)
        return 0 == len(errors)

    async def _validate_email(self, address):
        val = await self.loop.run_in_executor(None, validate_email, address)
        return val["email"]

    async def validate_emails(self):
        errors = {}
        if "sendToEmails" not in self.data or 0 == len(self.data["sendToEmails"]):
            errors["sendToEmails"] = "Send to email addresses not given or empty"
        else:
            try:
                collected_emails = []
                valid_domains = self.config.valid_domains.split(",")
                for email in self.data["sendToEmails"].split(","):
                    validated_email = await self._validate_email(email.strip())

                    matched = False
                    for valid_domain in valid_domains:
                        if validated_email.endswith(f"@{valid_domain.strip()}"):
                            collected_emails.append(validated_email)
                            matched = True
                            break

                    if not matched:
                        errors["sendToEmails"] = (
                            f"{validated_email} does not end with a valid domain - {valid_domains}"
                        )

                self.send_to_emails = ",".join(collected_emails)

            except EmailNotValidError:
                errors["sendToEmails"] = "Send to email contains an invalid email address"

        if "notifyEmail" not in self.data or 0 == len(self.data["notifyEmail"]):
            errors["notifyEmail"] = "Notification email not given or empty"
        else:
            try:
                self.notify_email = await self._validate_email(self.data["notifyEmail"])
            except EmailNotValidError:
                errors["notifyEmail"] = "Notification email is not a valid email address"

        self.errors.update(errors)
        return 0 == len(errors)

    @property
    def success(self):
        return 0 == len(self.errors)


class ViewBase(web.View):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._errors = {}
        self._data = {}
        self._messages = []

    @property
    def _cfg(self):
        return self.request.app["config"]

    @property
    def _wallabag(self):
        return self.request.app["wallabag"]

    def _template(self, variables):
        variables.update(
            {
                "errors": self._errors,
                "data": self._data,
                "messages": self._messages,
                "wallabag_host": self._cfg.wallabag_host,
                "tags": [t.tag for t in wallabag.make_tags(self._cfg.tag)],
            }
        )
        return variables

    def _add_errors(self, errors):
        self._errors.update(errors)

    def _set_data(self, data):
        self._data = data

    def _add_message(self, msg):
        self._messages.append(msg)

    @property
    def _session(self):
        return self.request.app["session_maker"]


class IndexView(ViewBase):
    @aiohttp_jinja2.template("index.html")
    async def get(self):
        return self._template({})

    @aiohttp_jinja2.template("index.html")
    async def post(self):
        data = await self.request.post()
        self._set_data(data)

        validator = Validator(self.request.app.loop, self._cfg, data)

        await asyncio.gather(validator.validate_emails(), validator.validate_credentials())
        self._add_errors(validator.errors)

        if validator.success:
            user = models.User(
                name=validator.username, send_to_emails=validator.send_to_emails, email=validator.notify_email
            )

            with self._session as session:
                if session.query(models.User.name).filter(models.User.name == validator.username).count() != 0:
                    self._add_errors({"user": "User is already registered"})
                elif not await self._wallabag.get_token(user, validator.password):
                    self._add_errors({"auth": "Cannot authenticate at wallabag server to get a token"})
                else:
                    session.add(user)
                    session.commit()
                    self._add_message(f"User {validator.username} successfully registered")
                    self._set_data({})
                    logger.info("User {user} registered", user=validator.username)

        return self._template({})


class ReLoginView(ViewBase):
    @aiohttp_jinja2.template("relogin.html")
    async def get(self):
        return self._template({"action": "update", "description": "Refresh"})

    @aiohttp_jinja2.template("relogin.html")
    async def post(self):
        data = await self.request.post()
        self._set_data(data)

        validator = Validator(self.request.app.loop, self._cfg, data)
        await validator.validate_credentials()
        self._add_errors(validator.errors)

        if validator.success:
            with self._session as session:
                user = session.query(models.User).filter(models.User.name == validator.username).first()
                if user is None:
                    self._add_errors({"user": "User not registered"})
                else:
                    if await self._wallabag.get_token(user, validator.password):
                        user.active = True
                        session.commit()
                        self._add_message(f"User {validator.username} successfully updated.")
                        logger.info("User {user} successfully updated.", user=user)
                    else:
                        self._add_errors({"auth": "Authentication against wallabag server failed"})

        return self._template({"action": "update", "description": "Refresh"})


class DeleteView(ViewBase):
    @aiohttp_jinja2.template("relogin.html")
    async def get(self):
        return self._template({"action": "delete", "description": "Delete"})

    @aiohttp_jinja2.template("relogin.html")
    async def post(self):
        data = await self.request.post()
        self._set_data(data)

        validator = Validator(self.request.app.loop, self._cfg, data)
        await validator.validate_credentials()
        self._add_errors(validator.errors)

        if validator.success:
            with self._session as session:
                user = session.query(models.User).filter(models.User.name == validator.username).first()
                if user is None:
                    self._add_errors({"user": "User not registered"})
                else:
                    if await self._wallabag.get_token(user, validator.password):
                        session.delete(user)
                        session.commit()
                        self._add_message(f"User {validator.username} successfully deleted.")
                        logger.info("User {user} successfully deleted.", user=user)
                    else:
                        self._add_errors({"auth": "Authentication against wallabag server failed"})

        return self._template({"action": "delete", "description": "Delete"})


class App:
    def __init__(self, config, wallabag_client):
        self.config = config
        self.wallabag = wallabag_client
        self.app = web.Application()
        self.site = None  # type: web.TCPSite

        self.setup_app()
        self.setup_routes()

    def setup_app(self):
        self.app["config"] = self.config
        self.app["wallabag"] = self.wallabag
        self.app["session_maker"] = models.context_session(self.config)
        aiohttp_jinja2.setup(self.app, loader=jinja2.PackageLoader("wallabag_email_consumer", "templates"))

        self.app["static_root_url"] = "/static"

    def setup_routes(self):
        self.app.router.add_static("/static/", path=os.path.join(os.path.dirname(__file__), "static"), name="static")
        self.app.router.add_view("/", IndexView)
        self.app.router.add_view("/delete", DeleteView)
        self.app.router.add_view("/update", ReLoginView)

    def run(self):
        web.run_app(self.app, host=self.config.interface_host, port=self.config.interface_port)

    async def register_server(self):
        app_runner = web.AppRunner(self.app, access_log=logger)
        await app_runner.setup()
        self.site = web.TCPSite(app_runner, self.config.interface_host, self.config.interface_port)
        await self.site.start()

    def stop(self):
        if self.site is not None:
            asyncio.get_event_loop().create_task(self.site.stop())
