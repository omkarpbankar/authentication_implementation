FROM python:3.12-slim

WORKDIR /srv
COPY apps/app6_sso/saml_app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY apps/__init__.py apps/__init__.py
COPY apps/app6_sso/__init__.py apps/app6_sso/__init__.py
COPY apps/app6_sso/saml_app apps/app6_sso/saml_app
COPY tests/__init__.py tests/__init__.py
COPY tests/app6_saml tests/app6_saml

RUN useradd --create-home app && chown -R app /srv
USER app

EXPOSE 8007
CMD ["uvicorn", "apps.app6_sso.saml_app.main:production_app", "--factory", "--host", "0.0.0.0", "--port", "8007"]
