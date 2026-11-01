-- Test databases and roles for CI only. The passwords are public practice values.
CREATE ROLE platform_owner LOGIN PASSWORD 'owner-dev-password' NOSUPERUSER NOBYPASSRLS;
CREATE ROLE platform_app LOGIN PASSWORD 'app-dev-password' NOSUPERUSER NOBYPASSRLS;
CREATE ROLE platform_support LOGIN PASSWORD 'support-dev-password' NOSUPERUSER NOBYPASSRLS;
CREATE ROLE access_owner LOGIN PASSWORD 'access-owner-dev-password' NOSUPERUSER NOBYPASSRLS;
CREATE ROLE access_app LOGIN PASSWORD 'access-app-dev-password' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE platform_test OWNER platform_owner;
CREATE DATABASE access_test OWNER access_owner;
