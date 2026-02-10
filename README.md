# HelloID-Conn-Prov-Target-Aras-CardAccess
> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

> [!WARNING]
> Do not use this repository! There are still some questions that are being discussed with the supplier and customer. 

> [!WARNING]
> During testing, the API and/or the local machine on which CardAccess was installed were very slow. This does not necessarily apply to a production environment, but it is possible.

<p align="center">
  <img src="">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Aras-CardAccess](#helloid-conn-prov-target-aras-cardaccess)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported features](#supported-features)
  - [Getting started](#getting-started)
    - [HelloID Icon URL](#helloid-icon-url)
    - [Requirements](#requirements)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
    - [Persons, CardAccess and access](#persons-cardaccess-and-access)
    - [On-Premises Application](#on-premises-application)
    - [API Port Configuration](#api-port-configuration)
    - [BadgeOperation Endpoint](#badgeoperation-endpoint)
    - [Required AddBadge Fields](#required-addbadge-fields)
    - [Expiration Date Constraint](#expiration-date-constraint)
    - [Single Partition Support](#single-partition-support)
    - [Single Facility Configuration](#single-facility-configuration)
    - [AG Properties Limitation](#ag-properties-limitation)
    - [FirstName Field Mapping](#firstname-field-mapping)
    - [No Pagination Support](#no-pagination-support)
    - [Long audit message](#long-audit-message)
    - [Process for Granting and Receiving Physical Access Cards](#process-for-granting-and-receiving-physical-access-cards)
  - [Development resources](#development-resources)
    - [API endpoints](#api-endpoints)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Aras-CardAccess_ is a _target_ connector. _Aras-CardAccess_ provides a set of REST APIs that allow you to programmatically interact with its data.

## Supported features

The following features are available:

| Feature                                   | Supported | Actions                                 | Remarks |
| ----------------------------------------- | --------- | --------------------------------------- | ------- |
| **Account Lifecycle**                     | ✅         | Create, Update, Enable, Disable, Delete |         |
| **Permissions**                           | ✅         | Retrieve, Grant, Revoke                 |         |
| **Resources**                             | ❌         | -                                       |         |
| **Entitlement Import: Accounts**          | ✅         | -                                       |         |
| **Entitlement Import: Permissions**       | ✅         | -                                       |         |
| **Governance Reconciliation Resolutions** | ✅         | -                                       |         |

## Getting started

### HelloID Icon URL
URL of the icon used for the HelloID Provisioning target system.
```
https://raw.githubusercontent.com/Tools4everBV/HelloID-Conn-Prov-Target-ArasCardaccess/refs/heads/main/Icon.png
```

### Requirements

- **Aras CardAccess Installation**:<br>
  An Aras CardAccess system must be installed and configured on-premises. The connector requires access to the CardAccess API endpoints to manage badges and permissions.

- **HelloID Agent**:<br>
  A local agent is required for this connector. The connector only works when there is a local connection to the API and therefore does not function with the cloud agent.

- **Concurrent actions set to 1**: The grant and revoke permissions scripts use the `UpdateBadge` endpoint. This means that concurrent actions should be set to 1 to ensure all permissions are correctly set.

### Connection settings

The following settings are required to connect to the API.

| Setting              | Description                                                   | Mandatory |
| -------------------- | ------------------------------------------------------------- | --------- |
| Username             | The Username to connect to the API                            | Yes       |
| Password             | The Password to connect to the API                            | Yes       |
| BaseUrl              | The URL to the API                                            | Yes       |
| PartitionId          | The PartitionId used to retrieve all badgeHolders             | Yes       |
| Facility             | The Facility on which the API requests will be executed        | Yes       |
| NoAccessPermissionId | The Permission Id (valueMember) of the 'no access' permission | Yes       |


- **PartitionId**:<br>
  To retrieve the partition ID, the API request `GET Partitions/AllPartitions` can be executed. For more information on the API request, please refer to the API documentation found at your local installation of CardAccess.

- **Facility**:<br>
  The Facility may be found in the CardAccess UI. During testing, `0` was used.

- **NoAccessPermissionId**:<br>
  To retrieve the 'no access' permission ID (valueMember), the API request `GET Access/AccessGroups` can be executed. For more information on the API request, please refer to the API documentation found at your local installation of CardAccess.

### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _Aras-CardAccess_ to a person in _HelloID_.

| Setting                   | Value                             |
| ------------------------- | --------------------------------- |
| Enable correlation        | `True`                            |
| Person correlation field  | `PersonContext.Person.ExternalId` |
| Account correlation field | `Badge`                           |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

### Account Reference

The account reference is populated with the `Badge` property from _Aras-CardAccess_.

## Remarks

### Persons, CardAccess and access
- **Connector functionality**: The connector creates badge holders in Aras CardAccess based on persons in HelloID with a one-to-one relationship (one HelloID person equals one badge holder), where each badge holder can have multiple active permissions stored directly on the badge holder object, and although Aras CardAccess also supports creating persons via its API, persons are not used by this connector.

### On-Premises Application
- **Installation Type**: The connector is designed for an on-premises Aras CardAccess installation, not cloud-based deployments. This means an agent should be configured.

### API Port Configuration
- **Default Port**: The API listens on port 8081 by default. If your instance uses a different port, update the BaseUrl connection setting accordingly.

### BadgeOperation Endpoint
- **Delete Operation**: The `BadgeOperation` endpoint is used for the delete action. Although it requires FirstName, LastName, and MiddleName as parameters, these name fields may be empty; only Badge and Facility are required to contain values. The request is a POST without a body.

### Required AddBadge Fields
- **Mandatory Fields**: The Facility ID, Badge, and LastName are mandatory fields for the AddBadge API request.

### Expiration Date Constraint
- **Date Behavior**: Expiration dates can be set to null during account creation, but once set, they cannot be changed back to null. The connector therefore always includes both activation and expiration dates in enable and disable operations.

### Single Partition Support
- **Partition Limitation**: The connector currently supports only one partition ID for the `AllBadgeHolders` endpoint. If your configuration uses multiple partitions, the connector code must be modified to handle them appropriately.
  
### Single Facility Configuration
- **Facility Scope**: The connector is currently configured to work with a single facility number only. Modifications to the connector are required to support multiple facilities.
- **Facility Scope**: Because the connector supports only one facility, it does not correlate existing badge holders that were created in other facilities.

### AG Properties Limitation
- **Property Limit**: The data model supports a maximum of 16 `AG#` properties. Behavior is undefined if more than 16 `accessGroups` are assigned to an account.
- **Grant no access during revoke**: It is not possible to revoke all permissions through the API without granting the `no access` permission. Because of this, the `no access` permission is granted in the `revokePermission` script when revoking the last remaining permission.

### FirstName Field Mapping
- **Field Conversion**: The connector operation includes special mapping to convert the property "FrstName" to "FirstName" to match API requirements.

### No Pagination Support
- **Bulk Retrieval**: The GetAllBadgeHolders endpoint does not support pagination, so all accounts are retrieved in a single request.

### Long audit message
- **Error message max length**: The API sometimes returns a very long error message. Since HelloID doesn't support long audit log messages, messages are capped at 254 characters.

### Process for Granting and Receiving Physical Access Cards
- Because the **Badge** property is used as a correlation field, issues may occur when the *CardAccess* property **Badge** is populated with a field from the source system that contains the physical badge number.
  
  Persons remain in HelloID (depending on the configured retention period) for up to one month after they leave the organization. During this period, HelloID retains which badge/card number belongs to that person.
  
  If an employee leaves the organization and the physical badge is reassigned to a new employee within that month, this can result in two HelloID persons being correlated to a single badge holder.

## Development resources

### API endpoints

The following endpoints are used by the connector.

| Endpoint                | Method | Description                                 |
| ----------------------- | ------ | ------------------------------------------- |
| /token                  | POST   | Authenticate and retrieve access token      |
| /Badges/AllBadgeHolders | GET    | Retrieve all badge holders (accounts)       |
| /Badges/BadgeInfo       | GET    | Retrieve specific badge/account information |
| /Badges/AddBadge        | POST   | Create a new badge/account                  |
| /Badges/UpdateBadge     | POST   | Update badge/account information            |
| /Badges/BadgeOperation  | POST   | Delete/manage badge operations              |
| /Access/AccessGroups    | GET    | Retrieve access groups (permissions)        |

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
