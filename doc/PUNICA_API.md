**Overview**
----
  This PUNICA provides easy to use interface to the LwM2M server and all LwM2M clients (devices) that are connected to it. One of the major issues with LwM2M is that clients may be often be unreachable (e.g. sleepy devices) and it's not possible to perform a direct transaction immediately. For this reason even channel model is used and all REST requests, that result in a (remote) transaction with a LwM2M client, return an asynchronous transaction id. Such calls are marked with **[async]** tag.
  
  Once such transaction is completed (or fails), an asynchronous response message is put into the event channel. The event channel should be regulary polled to retrieve the queued events. If polling is undesired, or better time response is needed, the application can register an event callback address - in such case this REST service will send events immediately and directly to the registered address.
  
  Along with asynchronous responses, other events are also put into the event channel. These include registration, update and deregistration notifications. Event channel structure details can be found below, in the **Poll events** API call description.
  
  The PUNICA is similar to [MBED Device Connector API documentation](https://cloud.mbed.com/docs/v1.2/legacy-products/api-reference.html) and many functions should be compatible, however some differences are to be expected.

**License**
----
The code in this directory is licensed under the MIT license, however please note that the application uses other libraries (including wakaama) that come under different licenses.

**List connected devices**
----
  Returns a list of devices, that are currently registered to the LwM2M service. Each device entry has a unique identifier (`name`), LwM2M queue mode status (`q`) and, if provided during device registration, a device type. It also has a status field, which must always be `ACTIVE`. If queue mode is enabled (`"q": true`) it means that the device is not accessible immeadiately and asynchronous requests (see below) will take longer to complete.

* **URL**

  /endpoints

* **Method:**
  
  `GET`

* **Success Response:**

  * **Code:** 200 <br />
    **Content:** `[{"name":"eui64-1d002a00-76656438","type":"8dev_3800","status":"ACTIVE","q":true},{"name":"eui64-19003c00-76656438","type":"8dev_4400","status":"ACTIVE","q":true}]`

* **Sample Call:**

  ```shell
  $ curl -X GET http://localhost:8888/endpoints
  ```
  
  
**List device objects**
----
  Returns a list of available object instances on the device. Each entry contains a path (`uri`) to a specific
  object instance available on the device. This list is provided by the device during registration to the LwM2M service.

* **URL**

  /endpoints/:name

* **Method:**

  `GET`

* **Success Response:**

  * **Code:** 200 <br />
    **Content:** `[{"uri":"/1/0"},{"uri":"/3/0"},{"uri":"/3200/0"},{"uri":"/3303/0"}]`
 
* **Error Response:**

  * **Code:** 404 NOT FOUND - endpoint with a provided name is not registered, has deregistered or timed-out<br />

* **Sample Call:**

  ```shell
  $ curl -X GET http://localhost:8888/endpoints/eui64-19003c00-76656438
  ```
  
**Read device resource(s) [async]**
----
  Schedules an asynchronous transaction to read a resource or object instance from the device.
  Returns transaction id (`async-response-id`), which will be used in the event channel (see below)
  to indicate a finished transaction.
  The path must be a valid LwM2M path to a resource (`/object_id/instance_id/resource_id`)
  or an object instance (`/object_id/instance_id`).

* **URL**

  /endpoints/:name/:path

* **Method:**

  `GET`

* **Success Response:**

  * **Code:** 202 <br />
    **Content:** `{"async-response-id":"1515412658#16ebc05b-2ad6-d805-3e01-50b8"}`
 
* **Error Response:**

  * **Code:** 404 NOT FOUND - the given path is invalid or does not exist <br />

  OR

  * **Code:** 410 GONE - the given endpoint does not exist <br />

* **Sample Call:**

  ```shell
  $ curl -X GET http://localhost:8888/endpoints/eui64-19003c00-76656438/3/0/2
  ```
  
  ```shell
  $ curl -X GET http://localhost:8888/endpoints/eui64-19003c00-76656438/3200/0
  ```

**Write device resource(s) [async]**
----
  Schedules an asynchronous transaction to write a resource or object instance to the device.
  Returns transaction id (`async-response-id`), which will be used in the event channel (see below)
  to indicate a finished transaction.
  The path must be a valid LwM2M path to a resource (`/object_id/instance_id/resource_id`)
  or an object instance (`/object_id/instance_id`).

* **URL**

  /endpoints/:name/:path

* **Method:**

  `PUT`
  
* **Data Params**

  Data must be encoded in LwM2M TLV format (see LwM2M specification) and the `Content-Type: application/vnd.oma.lwm2m+tlv` header must be set.

* **Success Response:**

  * **Code:** 202 <br />
    **Content:** `{"async-response-id":"1515415535#f5bf1bb1-eddd-ac3d-a633-2af4"}`
 
* **Error Response:**

  * **Code:** 404 NOT FOUND - the given path is invalid or does not exist <br />

  OR

  * **Code:** 410 GONE - the given endpoint does not exist <br />
  
  OR
  
  * **Code:** 410 UNSUPPORTED MEDIA TYPE - invalid data encoding format <br />

* **Sample Call:**

  ```shell
  $ echo -ne '\xC1\x03\x20' | curl http://localhost:8888/endpoints/eui64-19003c00-76656438/1/0/3 -X PUT -H "Content-Type: application/vnd.oma.lwm2m+tlv" --data-binary @-
  ```

**Execute device resource [async]**
----
  Schedules an asynchronous transaction to execute a resource on the device.
  Returns transaction id (`async-response-id`), which will be used in the event channel (see below)
  to indicate a finished transaction.
  The path must be a valid LwM2M path to a resource (`/object_id/instance_id/resource_id`).

* **URL**

  /endpoints/:name/:path

* **Method:**

  `POST`
  
* **Data Params**

  Data must be encoded in LwM2M opaque format (see LwM2M specification) and the `Content-Type: application/octet-stream` header must be set.

* **Success Response:**

  * **Code:** 202 <br />
    **Content:** `{"async-response-id":"1515415535#f5bf1bb1-eddd-ac3d-a633-2af4"}`
 
* **Error Response:**

  * **Code:** 404 NOT FOUND - the given path is invalid or does not exist <br />

  OR

  * **Code:** 410 GONE - the given endpoint does not exist <br />
  
  OR
  
  * **Code:** 410 UNSUPPORTED MEDIA TYPE - invalid data encoding format <br />

* **Sample Call:**

  ```shell
  $ curl http://localhost:8888/endpoints/eui64-19003c00-76656438/3/0/4 -X POST -H "Content-Type: application/octet-stream" --data-binary "Execute parameters"
  ```

**Observe device resource [async]**
----
  Schedules an asynchronous transaction to observe a resource from the device. Observed resource will send
  notifications whenever it's value changes or maximum observation period passes since last notification.
  
  Returns transaction id (`async-response-id`), which will be used in the event channel (see below)
  to indicate observation events.
  The path must be a valid LwM2M path to a resource (`/object_id/instance_id/resource_id`).

* **URL**

  /subscriptions/:name/:path

* **Method:**

  `PUT`

* **Success Response:**

  * **Code:** 202 <br />
    **Content:** `{"async-response-id":"1515412658#16ebc05b-2ad6-d805-3e01-50b8"}`
 
* **Error Response:**

  * **Code:** 404 NOT FOUND - the given endpoint name or path is invalid or does not exist <br />

* **Sample Call:**

  ```shell
  $ curl http://localhost:8888/subscriptions/eui64-19003c00-76656438/3200/0/5500 -X PUT
  ```

**Poll events**
----
  Returns all pending events and clears them from the event channel.
  Events are grouped into four types - [re-]registration (`registrations`), update (`reg-updates`), deregistrations (`de-registrations`) and
  asynchronous responses (`async-responses`).
  
  Registration, update and deregistration events contain an id (`name`) of the device which performed the corresponding event.
  Asyncronous response events are created when a response to a previously created asyncronous transaction is received from the device
  or an error happens, e.g. a transaction timeout. Asynchronous responses have an ID (given during async transaction creation),
  status code (`code`) and a base64 encoded payload.

* **URL**

  /notification/pull

* **Method:**

  `GET`

* **Success Response:**

  * **Code:** 200 <br />
    **Content:** 
    ```json
    {
      "registrations": [
        {"name": "eui64-1d002a00-76656438"}
      ],
      "reg-updates": [
        {"name": "eui64-1d002a00-76656438"},
        {"name": "eui64-19003c00-76656438"}
      ],
      "de-registrations": [
        {"name": "eui64-19003c00-76656438"}
      ],
      "async-responses": [
        {"id": "1515491879#bbd48aef-3211-a4b2-92e8-1f92", "status": 200, "payload": "wAI="}
      ]
    }
    ```

* **Sample Call:**

  ```shell
  curl http://localhost:8888/notification/pull
  ```

**Register callback**
----
  Registers a callback URL and parameters which will be used to send events as they are created on the event channel.

* **URL**

  /notification/callback

* **Method:**
  
  `PUT`
  
* **Data Params**

  Data must be a JSON object with `url` string of the callback address and `headers` object with optional key/value pairs
  that should be included in the callback request.

* **Success Response:**

  * **Code:** 204 <br />
 
* **Error Response:**

  * **Code:** 400 BAD REQUEST - one of following:
    - invalid JSON object format
    - given callback is not accessible
    - invalid headers provided
  <br />

  OR

  * **Code:** 415 UNSUPPORTED MEDIA TYPE - content type header is not "application/json" <br />

* **Sample Call:**

  ```shell
  $ curl http://localhost:8888/notification/callback -X PUT -H "Content-Type: application/json" --data '{"url": "http://localhost:9999/my_callback", "headers": {}}'
  ```

**Delete notification callback**
----
  Delete currently registered callback url and headers.

* **URL**

  /notification/callback

* **Method:**
  
  `DELETE`

* **Success Response:**

  * **Code:** 204 SUCCESS - Successfully removed callback <br />
 
* **Error Response:**

  * **Code:** 404 NOT FOUND - no callback is registered <br />

* **Sample Call:**

  ```shell
  $ curl http://localhost:8888/notification/callback -X DELETE
  ```

**Check notification callback**
----
  Retrieves currently registered callback url and headers.

* **URL**

  /notification/callback

* **Method:**
  
  `GET`

* **Success Response:**

  * **Code:** 200 <br />
    **Content:** `{"url":"http://localhost:9999/my_callback","headers":{}}`
 
* **Error Response:**

  * **Code:** 404 NOT FOUND - no callback is registered <br />

* **Sample Call:**

  ```shell
  $ curl http://localhost:8888/notification/callback
  ```

**Check [REST](./) API version**
----
  Retrieves current project version.

* **URL**

  /version

* **Method:**
  
  `GET`

* **Success Response:**

  * **Code:** 200 <br />
    **Content:** `MAJOR.MINOR.PATCH` <br />
    
1. MAJOR version when you make incompatible API changes,
2. MINOR version when you add functionality in a backwards-compatible manner, and
3. PATCH version when you make backwards-compatible bug fixes.

    [More information about semantic versioning](https://semver.org/)
 
* **Sample Call:**

  ```shell
  $ curl http://localhost:8888/version
  ```
  
**Authenticate JWT user**
  ----
  Retrieves JWT token issued for user (or error if authentication fails).

* **URL**

  /authenticate

* **Method:**
  
  `POST`

* **Success Response:**

  * **Code:** 201 <br />
    **Content:** `{"jwt":JWT_TOKEN_VALUE,"expires_in":JWT_EXPIRATION_TIME}` <br />
    - `JWT_TOKEN_VALUE` is described in [official JWT website](https://jwt.io/)
    - `JWT_EXPIRATION_TIME` time in seconds, after which client must renew his token
      
* **Error Response:**

  * **Code:** 400 Bad Request - JWT token wasn't granted, either credentials are invalid or message format is incorrect <br />
    **Content:** object with `error` key, which contains error status (`invalid_request` or `invalid_client`) <br />

* **Sample Call:**

  ```shell
  $ curl https://localhost:8888/authenticate -X POST -H "Content-Type: application/json" --data '{"name": "admin", "secret": "not-same-as-name"}'
  ```
  
  
**Authorize request with JWT**
  ----  
  Perform any request providing token from ``POST /authenticate`` response.
  *NOTE: If `jwt` section is not configured, jwt token (as well as authentication) is not required. `"GET /version"` request also doesn't require access token.*

  
  **Sample Call:**

  ```shell
  $ curl -X GET https://localhost:8888/endpoints/sensor-uuid/1/0/1 -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MzA3OTE1MDcsIm5hbWUiOiJhZG1pbiJ9.tk3B0J-rdPp8MyHqRHUWAtXjm0TsawBEfxQOoVEej0RQLQpt7oOp00Ocn3g44uCImq_hY26XhlGozceQ8Iarjg"
  ```
  
  Retrieves JWT token issued for user (or error if authentication fails).
  

* **URL**

  ``*`` (any URL)
  
* **Method:**
  
  ``*`` (any method)

* **Success Response:**

  On successful authorization, client receives response from requested resource URL. 
      
* **Error Response:**

  On unsuccessful authorization, client receives following response:

  * **Code:** 401 Unauthorized - JWT token wasn't granted, either credentials are invalid or message format is incorrect <br />
    **Content:** Empty body, ``WWW-Authenticate`` header containing error code and description <br />
  
[More information about JWT](https://jwt.io)
