package com.enel;

import java.util.UUID;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import java.io.IOException;
import com.sap.cloud.sdk.cloudplatform.connectivity.DestinationAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpClientAccessor;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import com.google.gson.Gson;
import org.apache.http.client.methods.HttpGet;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import javax.servlet.ServletException;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpDelete;
import java.io.BufferedReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//
@WebServlet("/SafetyDomainUsers/*")
@ServletSecurity(@HttpConstraint(rolesAllowed = { "scim_sc" }))
public class scimCustom extends HttpServlet {
	protected JsonArray membersNewArray;
	protected String direct;
	private JsonObject globalResponse = new JsonObject();
	private String globalError;
	private JsonObject customAttributes;
	private JsonObject customOut;
	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		response.setContentType("application/scim+json");
		try {
			String param = new String();
			String trust = "";

			param = request.getPathInfo().toString();
			String[] arrParam = param.split("/");
			if (arrParam[1].equals("Dev")) // check su origin
			{
				trust = "cfapps.eu10.hana.ondemand.comf137f15";
			} else if (arrParam[1].equals("Test")) {
			} else if (arrParam[1].equals("Prod")) {
			}

			String[] parametersArray = param.split("/Users");

			// if (request.getPathInfo() != null) {
			logger.error("lunghezza " + parametersArray.length + "campi "+ parametersArray[0]+ "PARAM" + param);
			
			if (parametersArray.length == 2) {
				param = request.getPathInfo().toString();
				// if (param.charAt(0) == '/') {
				// param = param.substring(1);
				String id = parametersArray[1].substring(1);

				HttpClient httpClient = HttpClientAccessor
						.getHttpClient(DestinationAccessor.getDestination("scimDomain"));

				// HttpGet getScim = new HttpGet("/Users/" + id);
				HttpGet getScim = new HttpGet("/Users/" + id);

				getScim.addHeader("Accept", "application/scim+json");
				HttpResponse scimResponse = httpClient.execute(getScim);
				if (scimResponse.getStatusLine().getStatusCode() == 200) {
					HttpEntity entityScim = scimResponse.getEntity();
					JsonObject jsonResponse = (JsonObject) new JsonParser().parse(EntityUtils.toString(entityScim));
					// version update
					String version = jsonResponse.getAsJsonObject("meta").get("version").toString();
					JsonObject meta2 = jsonResponse.getAsJsonObject("meta");
					meta2.remove("version");
					meta2.addProperty("version", version);
					jsonResponse.remove("meta");
					jsonResponse.add("meta", meta2);
					// version update
					JsonArray membersArray = jsonResponse.getAsJsonArray("groups");
					if (membersArray != null) {
						membersNewArray = new JsonArray();
						String direct;
						for (int i = 0; i < membersArray.size(); i++) {

							JsonObject member = new JsonObject();
							member = (JsonObject) membersArray.get(i);
							// if (member.get("value").toString().replace("\"", "").startsWith("IPDAIDA") ==
							// true) {
							//if (member.get("origin").toString().replace("\"", "").equals(trust)) { // check
																									// su
																									// origin
								direct = member.get("type").toString().replace("\"", "").toLowerCase();
								member.remove("type");
								member.addProperty("type", direct);
								membersNewArray.add(member);
								// }
							//}
						}

						jsonResponse.remove("groups");
						jsonResponse.add("groups", membersNewArray);
					}
					if (jsonResponse.get("userName") != null) {
						String userAida = jsonResponse.get("userName").toString().replace("\"", "'");
						// String filter = "?$filter=USER%20eq%20" + userAida + "&$format=json";
						String lowUserAida = userAida.toLowerCase().replace("\"", "'");
						String filter = "?$filter=tolower(USER)%20eq%20" + lowUserAida + "&$format=json";
						// aggiungere i campi custom
						JsonArray arrayExtra = new JsonArray();
						// Get AIDA
						// String stringUrl = "/ROLES_ATTRIBUTES" + filter;
						// HttpClient httpClientAida = HttpClientAccessor
						// .getHttpClient(DestinationAccessor.getDestination("destinazioneApiManScimProt"));
						// HttpGet getAida = new HttpGet(stringUrl);
						// getAida.addHeader("Accept", "application/json");
						// HttpResponse aidaResponse = httpClientAida.execute(getAida);
						// HttpEntity entityAida = aidaResponse.getEntity();
						// JsonObject jsonResponseAida = (JsonObject) new JsonParser()
						// .parse(EntityUtils.toString(entityAida));
						// JsonArray jsonResponseAidaArray = jsonResponseAida.getAsJsonObject("d")
						// .getAsJsonArray("results");
						// JsonObject customAttributes = new JsonObject();
						// getCustomAttributes(jsonResponseAidaArray, customAttributes);
						// getCustomAttributes(jsonResponseAidaArray);
						jsonResponse.remove("schemas");
						jsonResponse.remove("approvals");
						jsonResponse.remove("verified");
						//jsonResponse.remove("origin");
						jsonResponse.remove("previousLogonTime");
						jsonResponse.remove("lastLogonTime");
						jsonResponse.remove("zoneId");
						jsonResponse.remove("passwordLastModified");

						// jsonResponse.remove("externalId");
						JsonArray schemasArray2 = new JsonArray();
						schemasArray2.add("urn:ietf:params:scim:schemas:core:2.0:User");
						// schemasArray2.add("urn:ietf:params:scim:schemas:extension:UAA:2.0:User");
						jsonResponse.add("schemas", schemasArray2);
						// jsonResponse.add("urn:ietf:params:scim:schemas:extension:UAA:2.0:User",
						// this.customAttributes);
						response.getWriter().write(new Gson().toJson(jsonResponse));
					}
				} else {
					response.setStatus(scimResponse.getStatusLine().getStatusCode());
					JsonObject jsonErrResp = (JsonObject) new JsonParser()
							.parse(EntityUtils.toString(scimResponse.getEntity()));
					// response.getWriter().write(new Gson().toJson(jsonErrResp));
				}
				// }
			} else {

				param = request.getPathInfo().toString();
				//logger.error("PARAM" + request.getQueryString());
				String filter = request.getQueryString();
				JsonObject jsonQueryResponse = this.queryScim(param, response, trust, filter);

				if (jsonQueryResponse != null) {
					response.getWriter().write(new Gson().toJson(jsonQueryResponse));
				}
			}
		} catch (Exception e) {
			response.setStatus(500);
			response.getWriter().append("Error: " + e.getMessage().toString());
		}

	}

	private void getCustomAttributes(JsonArray jsonResponseAidaArray) {
		this.customAttributes = new JsonObject();
		JsonArray areaArray = new JsonArray();
		JsonArray zonaArray = new JsonArray();
		JsonArray unitaArray = new JsonArray();
		for (int i = 0; i < jsonResponseAidaArray.size(); i++) {
			JsonObject aidaEl = (JsonObject) jsonResponseAidaArray.get(i);
			switch (aidaEl.get("ATTRIBUTE_NAME").toString().replace("\"", "")) {
			case "AreaCo":
				areaArray.add(aidaEl.get("ATTRIBUTE_VALUE").toString().replace("\"", ""));
				break;
			case "ZonaCo":
				zonaArray.add(aidaEl.get("ATTRIBUTE_VALUE").toString().replace("\"", ""));
				break;
			case "UnopCo":
				unitaArray.add(aidaEl.get("ATTRIBUTE_VALUE").toString().replace("\"", ""));
				break;
			default:
				break;

			}
			this.customAttributes.add("area", areaArray);
			this.customAttributes.add("zona", zonaArray);
			this.customAttributes.add("unita_operativa", unitaArray);
		}
	}

	private JsonObject queryScim(String param, HttpServletResponse response, String trust, String filter) throws IOException {
		HttpClient httpClient = HttpClientAccessor.getHttpClient(DestinationAccessor.getDestination("scimDomain"));
		HttpGet getScim;
		String filterOrig;
		//logger.error("PARAM" + param);
		
		logger.error("request data: " + filter);
		if (param != null) {
			if (filter != null && (filter.contains("filter") || filter.contains("count") || filter.contains("startIndex"))) {
				if (filter.contains("count") || filter.contains("startIndex")) {
					filterOrig = "%20&filter=%20origin%20eq%20%27" + trust + "%27";
				} else {
					filterOrig = "%20and%20origin%20eq%20%27" + trust + "%27";
				}
				logger.error("/Users?" + filter + filterOrig);
				getScim = new HttpGet("/Users?" + filter + filterOrig);

			} else {
				filterOrig = "filter=origin%20eq%20%27" + trust +"%27";
				logger.error("/Users?" + filterOrig + filter);
				getScim = new HttpGet("/Users?" + filterOrig + "&" + filter);
			}

		} else {
			filterOrig = "filter=%20origin%20eq%20%27" + trust + "%27";
			getScim = new HttpGet("/Users?" + filterOrig);
		}
		getScim.addHeader("Accept", "application/scim+json");
		HttpResponse scimResponse;
		try {
			scimResponse = httpClient.execute(getScim);
			HttpEntity entityScim = scimResponse.getEntity();
			JsonObject jsonResponseScim = (JsonObject) new JsonParser().parse(EntityUtils.toString(entityScim));
			JsonArray resources = jsonResponseScim.getAsJsonArray("resources");
			JsonArray newResources = new JsonArray();
			if (resources != null) {
				for (int i = 0; i < resources.size(); i++) {
					JsonObject scimRes = (JsonObject) resources.get(i);
					// JsonObject customAttributes = new JsonObject();
					// queryAida(scimRes.get("userName").toString().replace("\"", "'"));
					/*
					 * JsonObject jsonextra = new JsonObject(); if (arrayExtra != null) { if
					 * (arrayExtra.size() > 0) { jsonextra.add("extra", arrayExtra); } }
					 */
					scimRes.remove("previousLogonTime");
					scimRes.remove("lastLogonTime");
					scimRes.remove("approvals");
					scimRes.remove("verified");
					//scimRes.remove("origin");
					scimRes.remove("zoneId");
					scimRes.remove("passwordLastModified");
					// scimRes.remove("externalId");
					membersNewArray = new JsonArray();
					// version update

					//logger.error("Prima del GETADJSON" + scimRes.getAsJsonObject("meta"));
					String version = scimRes.getAsJsonObject("meta").get("version").toString();
					JsonObject meta2 = scimRes.getAsJsonObject("meta");
					meta2.remove("version");
					meta2.addProperty("version", version);
					scimRes.remove("meta");
					scimRes.add("meta", meta2);
					// version update
					JsonArray membersArray = scimRes.getAsJsonArray("groups");
					if (membersArray != null) {

						for (int j = 0; j < membersArray.size(); j++) {
							JsonObject member = new JsonObject();
							member = (JsonObject) membersArray.get(j);
							// if (member.get("value").toString().replace("\"", "").startsWith("IPDAIDA") ==
							// true) {
							//if (member.get("origin").toString().replace("\"", "").equals(trust)) { // check su origin

								direct = member.get("type").toString().replace("\"", "").toLowerCase();
								member.remove("type");
								member.addProperty("type", direct);
								membersNewArray.add(member);
							//}
						}

						scimRes.remove("groups");
						scimRes.add("groups", membersNewArray);
					}
					scimRes.remove("schemas");
					JsonArray schemasArray2 = new JsonArray();
					schemasArray2.add("urn:ietf:params:scim:schemas:core:2.0:User");
					// schemasArray2.add("urn:ietf:params:scim:schemas:extension:UAA:2.0:User");
					scimRes.add("schemas", schemasArray2);
					// scimRes.add("urn:ietf:params:scim:schemas:extension:UAA:2.0:User",
					// this.customAttributes);
					/*
					 * get con filtro non devono considerare AIDA if
					 * (scimRes.getAsJsonArray("groups").size() > 0 || membersArray == null ||
					 * membersArray.size() == 0) newResources.add(scimRes);
					 */

					//if (param != null && param.contains("=userName"))
					//	newResources.add(scimRes);
					//else if (scimRes.getAsJsonArray("groups").size() > 0 || membersArray == null
					//		|| membersArray.size() == 0)
						newResources.add(scimRes);
				}
				jsonResponseScim.remove("resources");
				jsonResponseScim.add("Resources", newResources);

			}
			jsonResponseScim.remove("schemas");
			JsonArray schemasArray2 = new JsonArray();
			schemasArray2.add("urn:ietf:params:scim:api:messages:2.0:ListResponse");
			// schemasArray2.add("urn:ietf:params:scim:schemas:extension:UAA:2.0:User");
			jsonResponseScim.add("schemas", schemasArray2);
			// jsonResponseScim.remove("totalResults");
			// jsonResponseScim.addProperty("totalResults",
			// jsonResponseScim.getAsJsonArray("Resources").size());
			return jsonResponseScim;
		} catch (IOException e) {
			response.setStatus(500);
			response.getWriter().append("Error: " + e.getMessage().toString());
			return null;
		}

	}

	private void queryAida(String username) {
		try {
			// String filter = "?$filter=USER%20eq%20" + username + "&$format=json";
			String lowUserAida = username.toLowerCase().replace("\"", "'");
			String filter = "?$filter=tolower(USER)%20eq%20" + lowUserAida + "&$format=json";
			JsonArray arrayExtra = new JsonArray();
			String stringUrl = "/ROLES_ATTRIBUTES" + filter;
			HttpClient httpClientAida = HttpClientAccessor
					.getHttpClient(DestinationAccessor.getDestination("destinazioneApiManScimProt"));
			HttpGet getAida = new HttpGet(stringUrl);
			HttpResponse aidaResponse;
			aidaResponse = httpClientAida.execute(getAida);
			HttpEntity entityAida = aidaResponse.getEntity();
			JsonObject jsonResponseAida = (JsonObject) new JsonParser().parse(EntityUtils.toString(entityAida));
			JsonArray jsonResponseAidaArray = jsonResponseAida.getAsJsonObject("d").getAsJsonArray("results");
			// getCustomAttributes(jsonResponseAidaArray, customAttributes);
			getCustomAttributes(jsonResponseAidaArray);
		} catch (ClientProtocolException e) {

		} catch (IOException e) {

		}
	}

	private Integer put(String destination, String trust, String master, StringBuffer jb, String userName)
			throws ServletException, IOException {
		try {
			String param;
			JsonObject jsonResponse = new JsonObject();
			JsonObject newObject = new JsonParser().parse(jb.toString()).getAsJsonObject();
			JsonObject newObject2 = newObject.deepCopy();
			Integer status = 0;
			HttpClient httpClient = HttpClientAccessor.getHttpClient(DestinationAccessor.getDestination(destination));
			JsonArray membersNewArray = new JsonArray();
			/////////////////////////// inserire i gruppi diversi da AIDA
			String filterUser = "?filter=userName%20eq%20" + userName;
			HttpGet getGroups = new HttpGet("/Users" + filterUser);
			getGroups.addHeader("Accept", "application/scim+json");
			HttpResponse getGroupsResponse = httpClient.execute(getGroups);
			HttpEntity entityGroups = getGroupsResponse.getEntity();
			JsonObject jsonResponseGroups = (JsonObject) new JsonParser().parse(EntityUtils.toString(entityGroups));
			JsonArray resArray = jsonResponseGroups.getAsJsonArray("resources");
			JsonObject jsonResponseGroups0 = new JsonObject();
			logger.error("11111111" + filterUser);
			for (int i = 0; i < resArray.size(); i++) {
				JsonObject resArrayObject = (JsonObject) resArray.get(i);
				if (resArrayObject.get("origin").toString().replace("\"", "").equals(trust)) {
					jsonResponseGroups0 = resArrayObject;
					break;
				}
			}

			JsonArray membersArrayGroups = jsonResponseGroups0.getAsJsonArray("groups");
			// proviamo a non far aggiungere gruppi vecchi
			if (membersArrayGroups != null) {
				for (int i = 0; i < membersArrayGroups.size(); i++) {
					JsonObject memberGroup = new JsonObject();
					memberGroup = (JsonObject) membersArrayGroups.get(i);
					// if (memberGroup.get("value").toString().replace("\"",
					// "").startsWith("IPDAIDA") == false)
					//if (memberGroup.get("origin").toString().replace("\"", "").equals(trust)) // check su origin
						membersNewArray.add(memberGroup);
				}
			}

			/////////////////////////// inserire i gruppi diversi da AIDA
			param = jsonResponseGroups0.get("id").toString().replace("\"", "");
			HttpPut requestScim = new HttpPut("/Users/" + param);
			requestScim.addHeader("content-type", "application/scim+json");
			JsonArray membersArray = newObject2.getAsJsonArray("groups");
			if (membersArray != null) {
				for (int i = 0; i < membersArray.size(); i++) {
					JsonObject member = new JsonObject();
					member = (JsonObject) membersArray.get(i);
					direct = member.get("type").toString().replace("\"", "").toUpperCase();
					member.remove("type");
					member.addProperty("type", direct);
					membersNewArray.add(member);
				}
				newObject.remove("groups");
				newObject.add("groups", membersNewArray);
			}
			// direct in put
			requestScim.addHeader("If-Match", "*");
			// newObject.remove("urn:ietf:params:scim:schemas:extension:UAA:2.0:User");
			newObject.remove("schemas");
			JsonArray schemasArray = new JsonArray();
			schemasArray.add("urn:scim:schemas:core:1.0");
			newObject.add("schemas", schemasArray);
			newObject.addProperty("origin", trust);
			newObject.remove("id");
			StringEntity paramsScim = new StringEntity(newObject.toString());
			requestScim.setEntity(paramsScim);
			HttpResponse responseScim = httpClient.execute(requestScim);
			if (responseScim.getStatusLine().getStatusCode() == 200 && master == "X") {
				HttpEntity entityScim = responseScim.getEntity();
				if (entityScim != null) {
					String responseScimJson = EntityUtils.toString(entityScim);
					status = 200;
					jsonResponse = (JsonObject) new JsonParser().parse(responseScimJson);
					// JsonObject custom = newObject2
					// .getAsJsonObject("urn:ietf:params:scim:schemas:extension:UAA:2.0:User");
					// JsonObject customOut = new JsonObject();
					// JsonArray extraArrayOut = new JsonArray();
					// if (custom != null) {
					// cancello da aida con filtro
					//// this.deleteAida(newObject.get("userName").toString());
					// JsonArray extraArray = custom.getAsJsonArray("extra");
					//// insertAida(newObject.get("userName").toString(), custom);

					// }
					// jsonResponse.add("urn:ietf:params:scim:schemas:extension:UAA:2.0:User",
					// this.customOut);
					jsonResponse.remove("schemas");
					jsonResponse.remove("approvals");
					jsonResponse.remove("verified");
					jsonResponse.remove("origin");
					jsonResponse.remove("zoneId");
					jsonResponse.remove("previousLogonTime");
					jsonResponse.remove("lastLogonTime");
					jsonResponse.remove("passwordLastModified");
					// jsonResponse.remove("externalId");
					JsonArray schemasArray2 = new JsonArray();
					schemasArray2.add("urn:ietf:params:scim:schemas:core:2.0:User");
					// schemasArray2.add("urn:ietf:params:scim:schemas:extension:UAA:2.0:User");
					jsonResponse.add("schemas", schemasArray2);
					membersNewArray = new JsonArray();
					// version update
					String version = jsonResponse.getAsJsonObject("meta").get("version").toString();
					JsonObject meta2 = jsonResponse.getAsJsonObject("meta");
					meta2.remove("version");
					meta2.addProperty("version", version);
					jsonResponse.remove("meta");
					jsonResponse.add("meta", meta2);
					// version update
					membersArray = jsonResponse.getAsJsonArray("groups");
					if (membersArray != null) {

						for (int i = 0; i < membersArray.size(); i++) {
							JsonObject member = new JsonObject();
							member = (JsonObject) membersArray.get(i);
							// if (member.get("value").toString().replace("\"", "").startsWith("IPDAIDA") ==
							// true) {
							//if (member.get("origin").toString().replace("\"", "").equals(trust)) { // check su origin
								direct = member.get("type").toString().replace("\"", "").toLowerCase();
								member.remove("type");
								member.addProperty("type", direct);
								membersNewArray.add(member);
							//}
						}
						jsonResponse.remove("groups");
						jsonResponse.add("groups", membersNewArray);
					}
					// response.getWriter().write(new Gson().toJson(jsonResponse));
					globalResponse = jsonResponse;
				}
			} else {
				status = responseScim.getStatusLine().getStatusCode();
				this.globalError = status.toString();
				// JsonObject jsonErrResp = (JsonObject) new JsonParser()
				// .parse(EntityUtils.toString(responseScim.getEntity()));
				// response.getWriter().write(new Gson().toJson(jsonErrResp));
			}
			return status;
		} catch (Exception e) {
			this.globalError = e.getMessage().toString();
			return 500;

		}
	}

	protected void doPut(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		response.setContentType("application/scim+json");
		try {
			String param = request.getPathInfo().toString();
			String[] arrParam = param.split("/");
			String trust = "";

			if (arrParam[1].equals("Dev")) // check su origin
			{
				trust = "cfapps.eu10.hana.ondemand.comf137f15";
			} else if (arrParam[1].equals("Test")) {
			} else if (arrParam[1].equals("Prod")) {
			}

			String[] parametersArray = param.split("/Users");

			// JsonObject newObject = new JsonObject();
			StringBuffer jb = new StringBuffer();
			String line = null;
			response.setContentType("application/scim+json");
			BufferedReader reader = request.getReader();
			while ((line = reader.readLine()) != null) {
				jb.append(line);
			}
			// newObject = new JsonParser().parse(jb.toString()).getAsJsonObject();
			// JsonObject newObject2 = newObject.deepCopy();
			// String param = request.getPathInfo().toString();

			// if (param.charAt(0) == '/') {
			//logger.error("ooooo"+parametersArray.length + "    " +parametersArray[1] + "username" + user.get("userName").toString());
			if (parametersArray.length == 2) {
				JsonObject user = new JsonParser().parse(jb.toString()).getAsJsonObject();
				String userName = user.get("userName").toString().replace("\"", "'");
				logger.error("username  "+userName);
				
				param = param.substring(1);

				// JsonObject jsonResponse = new JsonObject();
				// if (this.put("scim", "afqxozn24.accounts.ondemand.com", "", jb, userName) ==
				// 200) { PROD
				// if (this.put("scim", "anev3ox8b.accounts.ondemand.com", "", jb, userName) ==
				// 200) { // DEV

				// if (this.put("scim", "cfapps.eu10.hana.ondemand.com46ae131", "", jb,
				// userName) == 200) { PROD
				// if (this.put("scim", "cfapps.eu10.hana.ondemand.com4a795a7", "", jb,
				// userName) == 200) { // DEV
				// Integer stat = this.put("scimDomain", "afqxozn24.accounts.ondemand.com", "X",
				// jb, userName); PROD
				Integer stat = this.put("scimDomain", trust, "X", jb, userName); // DEV
				response.setStatus(stat);
				if (stat == 200)
					response.getWriter().write(new Gson().toJson(globalResponse));
				else {

					JsonObject error = new JsonObject();
					error.addProperty("error3", globalError);
					response.getWriter().write(new Gson().toJson(error));
					response.setStatus(500);

				}
				/*
				 * } else {
				 * 
				 * JsonObject error = new JsonObject(); error.addProperty("error2",
				 * globalError); response.getWriter().write(new Gson().toJson(error));
				 * 
				 * response.setStatus(500); }
				 */
				/*
				 * } else {
				 * 
				 * JsonObject error = new JsonObject(); error.addProperty("error1",
				 * globalError); response.getWriter().write(new Gson().toJson(error));
				 * response.setStatus(500); }
				 */
			}
		} catch (Exception e) {
			response.setStatus(500);
			JsonObject error = new JsonObject();
			error.addProperty("error_catch", "X");
			response.getWriter().write(new Gson().toJson(error));
		}
	}

	private void insertAida(String userName, JsonObject custom) {

		// Username To Uppercase

		String userNameUp = userName;
		userNameUp.toUpperCase();

		this.customOut = new JsonObject();
		JsonArray areaArray = custom.getAsJsonArray("area");
		JsonArray zonaArray = custom.getAsJsonArray("zona");
		JsonArray unitaArray = custom.getAsJsonArray("unita_operativa");
		JsonArray areaArrayOut = new JsonArray();
		JsonArray zonaArrayOut = new JsonArray();
		JsonArray unitaArrayOut = new JsonArray();
		if (areaArray != null) {
			for (int i = 0; i < areaArray.size(); i++) {
				if (createRecordAida(userNameUp, areaArray.get(i).toString(), "AreaCo")) {
					areaArrayOut.add(areaArray.get(i).toString().replace("\"", "'"));
				}
			}
		}
		if (zonaArray != null) {
			for (int i = 0; i < zonaArray.size(); i++) {
				if (createRecordAida(userNameUp, zonaArray.get(i).toString(), "ZonaCo"))

					zonaArrayOut.add(zonaArray.get(i).toString().replace("\"", "'"));
			}
		}
		if (unitaArray != null) {
			for (int i = 0; i < unitaArray.size(); i++) {
				if (createRecordAida(userNameUp, unitaArray.get(i).toString(), "UnopCo"))

					unitaArrayOut.add(unitaArray.get(i).toString().replace("\"", "'"));
			}
		}
		this.customOut.add("area", areaArrayOut);
		this.customOut.add("zona", zonaArrayOut);
		this.customOut.add("unita_operativa", unitaArrayOut);
	}

	private boolean createRecordAida(String user, String value, String attribute) {
		JsonObject customAttrAida = new JsonObject();
		customAttrAida.addProperty("USER", user.replace("\"", ""));
		customAttrAida.addProperty("ATTRIBUTE_VALUE", value.replace("\"", ""));
		customAttrAida.addProperty("ATTRIBUTE_NAME", attribute.replace("\"", ""));
		StringEntity paramsAida = new StringEntity(customAttrAida.toString(), "UTF-8");
		HttpPost requestAida = new HttpPost("/ROLES_ATTRIBUTES");
		requestAida.addHeader("content-type", "application/json");
		requestAida.setEntity(paramsAida);
		HttpClient httpClientAida = HttpClientAccessor
				.getHttpClient(DestinationAccessor.getDestination("destinazioneApiManScimProt"));
		HttpResponse responseAida;
		try {
			responseAida = httpClientAida.execute(requestAida);
			if (responseAida.getStatusLine().getStatusCode() == 201)
				return true;
			else
				return false;
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			return false;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			return false;
		}

	}

	private void deleteAida(String userName) {
		try {
			// String filter = "?$filter=USER%20eq%20" + userName.replace("\"", "'") +
			// "&$format=json";
			String lowUserAida = userName.toLowerCase().replace("\"", "'");
			String filter = "?$filter=tolower(USER)%20eq%20" + lowUserAida + "&$format=json";
			String stringUrl = "/ROLES_ATTRIBUTES" + filter;
			HttpClient httpClientAida = HttpClientAccessor
					.getHttpClient(DestinationAccessor.getDestination("destinazioneApiManScimProt"));
			HttpGet getAida = new HttpGet(stringUrl);
			HttpResponse aidaResponse;
			aidaResponse = httpClientAida.execute(getAida);

			HttpEntity entityAida = aidaResponse.getEntity();
			JsonObject jsonResponseAida = (JsonObject) new JsonParser().parse(EntityUtils.toString(entityAida));
			JsonArray jsonResponseAidaArray = jsonResponseAida.getAsJsonObject("d").getAsJsonArray("results");
			for (int i = 0; i < jsonResponseAidaArray.size(); i++) {
				JsonObject aidaEl = (JsonObject) jsonResponseAidaArray.get(i);
				String path = "(USER=" + aidaEl.get("USER").toString().replace("\"", "'") + ",ATTRIBUTE_NAME="
						+ aidaEl.get("ATTRIBUTE_NAME").toString().replace("\"", "'") + ",ATTRIBUTE_VALUE="
						+ aidaEl.get("ATTRIBUTE_VALUE").toString().replace("\"", "'") + ")";
				HttpDelete requestAidaDelete = new HttpDelete("/ROLES_ATTRIBUTES" + path);
				httpClientAida.execute(requestAidaDelete);
			}
		} catch (ClientProtocolException e) {

		} catch (IOException e) {

		}
	}

	private Integer delete(String destination, String master, String param, String trust, String userName) {
		Integer status = 0;
		try {
			HttpClient httpClient = HttpClientAccessor.getHttpClient(DestinationAccessor.getDestination(destination));
			/////////// recupero id corretto

			String filterUser = "?filter=userName%20eq%20" + userName;
			HttpGet getListUsers = new HttpGet("/Users" + filterUser);
			getListUsers.addHeader("Accept", "application/scim+json");
			HttpResponse getListUsersResponse = httpClient.execute(getListUsers);
			HttpEntity entityListUsers = getListUsersResponse.getEntity();
			JsonObject jsonResponseUsers = (JsonObject) new JsonParser().parse(EntityUtils.toString(entityListUsers));
			JsonArray jsonResponseUsersArray = jsonResponseUsers.getAsJsonArray("resources");
			String ok = "";
			for (int i = 0; i < jsonResponseUsersArray.size(); i++) {
				JsonObject userEl = (JsonObject) jsonResponseUsersArray.get(i);
				if (userEl.get("origin").toString().replace("\"", "").equals(trust)) {
					String newParam = userEl.get("id").toString().replace("\"", "");
					/////////// recupero id corretto
					HttpDelete requestScim = new HttpDelete("/Users/" + newParam);
					requestScim.addHeader("If-Match", "*");
					HttpResponse responseScim = httpClient.execute(requestScim);
					if (responseScim.getStatusLine().getStatusCode() == 200
							|| responseScim.getStatusLine().getStatusCode() == 404) {
						ok = "X";
						if (master == "X") {
							HttpEntity entityScim = responseScim.getEntity();
							JsonObject jsonResponseScim = (JsonObject) new JsonParser()
									.parse(EntityUtils.toString(entityScim));
							if (jsonResponseScim.get("userName") != null) {
								// String userAida = jsonResponseScim.get("userName").toString().replace("\"",
								// "'");
								// String filter = "?$filter=USER%20eq%20" + userAida + "&$format=json";
								// String lowUserAida = userAida.toLowerCase().replace("\"", "'");
								// String filter = "?$filter=tolower(USER)%20eq%20" + lowUserAida +
								// "&$format=json";
								// JsonArray arrayExtra = new JsonArray();
								// String stringUrl = "/ROLES_ATTRIBUTES" + filter;
								// HttpClient httpClientAida = HttpClientAccessor.getHttpClient(
								// DestinationAccessor.getDestination("destinazioneApiManScimProt"));
								// HttpGet getAida = new HttpGet(stringUrl);
								// HttpResponse aidaResponse = httpClientAida.execute(getAida);
								// HttpEntity entityAida = aidaResponse.getEntity();
								// JsonObject jsonResponseAida = (JsonObject) new JsonParser()
								// .parse(EntityUtils.toString(entityAida));
								// JsonArray jsonResponseAidaArray = jsonResponseAida.getAsJsonObject("d")
								// .getAsJsonArray("results");
								// for (i = 0; i < jsonResponseAidaArray.size(); i++) {
								// JsonObject aidaEl = (JsonObject) jsonResponseAidaArray.get(i);
								// String path = "(USER=" + aidaEl.get("USER").toString().replace("\"", "'")
								// + ",ATTRIBUTE_NAME="
								// + aidaEl.get("ATTRIBUTE_NAME").toString().replace("\"", "'")
								// + ",ATTRIBUTE_VALUE="
								// + aidaEl.get("ATTRIBUTE_VALUE").toString().replace("\"", "'") + ")";
								// HttpDelete requestAidaDelete = new HttpDelete("/ROLES_ATTRIBUTES" + path);
								// httpClientAida.execute(requestAidaDelete);
								// }
							}
						}
						break;
					}
				}
			}
			if (ok == "X") {
				status = 200;
				if (master == "X")
					status = 204;
				return status;
			} else
				return 500;
		} catch (Exception e) {
			return 500;
		}
	}

	protected void doDelete(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		response.setContentType("application/scim+json");
		try {
			String param = request.getPathInfo().toString();
			String trust = "";

			String[] arrParam = param.split("/");
			if (arrParam[1].equals("Dev")) // check su origin
			{
				trust = "cfapps.eu10.hana.ondemand.comf137f15";
			} else if (arrParam[1].equals("Test")) {
			} else if (arrParam[1].equals("Prod")) {
			}

			String[] parametersArray = param.split("/Users");
			// if (param.charAt(0) == '/') {
			if (parametersArray.length == 2) {
				//param = param.substring(1);
				param = parametersArray[1].substring(1);
				
				HttpClient httpClientCross = HttpClientAccessor
						.getHttpClient(DestinationAccessor.getDestination("scimDomain"));
				HttpGet getUser = new HttpGet("/Users/" + param);
				getUser.addHeader("Accept", "application/scim+json");
				HttpResponse userResponse = httpClientCross.execute(getUser);
				HttpEntity entityUser = userResponse.getEntity();
				JsonObject jsonResponseUser = (JsonObject) new JsonParser().parse(EntityUtils.toString(entityUser));
				String userName = jsonResponseUser.get("userName").toString().replace("\"", "'");

				response.setStatus(
						// this.delete("scimDomain", "X", param, "afqxozn24.accounts.ondemand.com",
						// userName));
						this.delete("scimDomain", "X", param, trust, userName));
				// } else
				// response.setStatus(500);
				// } else
				// response.setStatus(500);

			}
		} catch (Exception e) {
			response.setStatus(500);
			response.getWriter().append("Error: " + e.getMessage().toString());
		}

	}

	private Integer post(String destination, String trust, String master, StringBuffer jb) {
		Integer status = 0;
		JsonObject jsonResponse = new JsonObject();
		try {

			JsonObject newObject = new JsonParser().parse(jb.toString()).getAsJsonObject();

			JsonObject newObject2 = newObject.deepCopy();
			membersNewArray = new JsonArray();

			// direct in post
			JsonArray membersArray = newObject2.getAsJsonArray("groups");
			if (membersArray != null) {

				for (int i = 0; i < membersArray.size(); i++) {
					JsonObject member = new JsonObject();
					member = (JsonObject) membersArray.get(i);
					direct = member.get("type").toString().replace("\"", "").toUpperCase();
					member.remove("type");
					member.addProperty("type", direct);
					membersNewArray.add(member);
				}
				newObject.remove("groups");
				newObject.add("groups", membersNewArray);
			}
			// direct in post

			HttpClient httpClient = HttpClientAccessor.getHttpClient(DestinationAccessor.getDestination(destination));
			HttpPost requestScim = new HttpPost("/Users");
			requestScim.addHeader("content-type", "application/scim+json");
			// newObject.remove("urn:ietf:params:scim:schemas:extension:UAA:2.0:User");
			newObject.remove("schemas");
			newObject.addProperty("ID", UUID.randomUUID().toString());
			newObject.addProperty("origin", trust);
			JsonArray schemasArray = new JsonArray();
			schemasArray.add("urn:scim:schemas:core:1.0");
			newObject.add("schemas", schemasArray);
			StringEntity paramsScim = new StringEntity(newObject.toString());
			requestScim.setEntity(paramsScim);
			HttpResponse responseScim = httpClient.execute(requestScim);
			if (responseScim.getStatusLine().getStatusCode() == 201 && master == "X") {
				// chiamata AIDA
				HttpEntity entityScim = responseScim.getEntity();
				if (entityScim != null) {
					String responseScimJson = EntityUtils.toString(entityScim);
					status = 201;
					jsonResponse = (JsonObject) new JsonParser().parse(responseScimJson);
					// HttpClient httpClientAida = HttpClientAccessor
					// .getHttpClient(DestinationAccessor.getDestination("destinazioneApiManScimProt"));

					// JsonObject custom = newObject2
					// .getAsJsonObject("urn:ietf:params:scim:schemas:extension:UAA:2.0:User");
					// JsonObject customOut = new JsonObject();
					// JsonArray extraArrayOut = new JsonArray();
					// if (custom != null) {
					// insertAida(newObject.get("userName").toString(), custom);
					// }
					// jsonResponse.add("urn:ietf:params:scim:schemas:extension:UAA:2.0:User",
					// this.customOut);
					jsonResponse.remove("schemas");
					jsonResponse.remove("approvals");
					jsonResponse.remove("verified");
					jsonResponse.remove("previousLogonTime");
					jsonResponse.remove("lastLogonTime");
					jsonResponse.remove("origin");
					jsonResponse.remove("zoneId");
					jsonResponse.remove("passwordLastModified");

					membersArray = jsonResponse.getAsJsonArray("groups");
					membersNewArray = new JsonArray();

					if (membersArray != null) {

						for (int i = 0; i < membersArray.size(); i++) {
							JsonObject member = new JsonObject();
							member = (JsonObject) membersArray.get(i);
							// if (member.get("value").toString().replace("\"", "").startsWith("IPDAIDA") ==
							// true) {
							direct = member.get("type").toString().replace("\"", "").toLowerCase();
							member.remove("type");
							member.addProperty("type", direct);
							membersNewArray.add(member);
							// }
						}
						jsonResponse.remove("groups");
						jsonResponse.add("groups", membersNewArray);
					}
					// jsonResponse.remove("externalId");
					JsonArray schemasArray2 = new JsonArray();
					schemasArray2.add("urn:ietf:params:scim:schemas:core:2.0:User");
					// schemasArray2.add("urn:ietf:params:scim:schemas:extension:UAA:2.0:User");
					jsonResponse.add("schemas", schemasArray2);
					// response.getWriter().write(new Gson().toJson(jsonResponse));
					globalResponse = jsonResponse;
				}
			} else

			{
				status = responseScim.getStatusLine().getStatusCode();

			}

			return status;
		} catch (Exception e) {
			return 500;
		}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		try {
			String param = request.getPathInfo().toString();
			String trust = "";

			String[] arrParam = param.split("/");
			if (arrParam[1].equals("Dev")) // check su origin
			{
				trust = "cfapps.eu10.hana.ondemand.comf137f15";
			} else if (arrParam[1].equals("Test")) {
			} else if (arrParam[1].equals("Prod")) {
			}

			// JsonObject newObject = new JsonObject();
			StringBuffer jb = new StringBuffer();
			String line = null;
			response.setContentType("application/scim+json");
			BufferedReader reader = request.getReader();
			while ((line = reader.readLine()) != null) {
				jb.append(line);
			}
			// JsonObject jsonResponse = new JsonObject();
			// Integer cr1 = this.post("scimDomain", "afqxozn24.accounts.ondemand.com", "",
			// jb); PROD
			// Integer cr1 = this.post("scimDomain", "anev3ox8b.accounts.ondemand.com", "",
			// jb);
			// if (cr1 == 201 || cr1 == 409) {
			// Integer cr2 = this.post("scim", "afqxozn24.accounts.ondemand.com", "", jb);
			// PROD
			// Integer cr2 = this.post("scim", "anev3ox8b.accounts.ondemand.com", "", jb);
			// if (cr2 == 201 || cr2 == 409) {
			// Integer stat = this.post("scim", "cfapps.eu10.hana.ondemand.com46ae131", "X",
			// jb); PROD
			Integer stat = this.post("scimDomain", trust, "X", jb);

			response.setStatus(stat);
			response.getWriter().write(new Gson().toJson(globalResponse));
			// } else
			// response.setStatus(500);
			// } else
			// response.setStatus(500);

		} catch (Exception e) {
			response.setStatus(500);
			response.getWriter().append("Error: " + e.getMessage().toString());
		}
	}

}
