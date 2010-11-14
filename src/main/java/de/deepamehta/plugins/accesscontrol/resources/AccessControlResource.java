package de.deepamehta.plugins.accesscontrol.resources;

import de.deepamehta.plugins.accesscontrol.AccessControlPlugin;
import de.deepamehta.plugins.accesscontrol.AccessControlPlugin.Role;
import de.deepamehta.plugins.accesscontrol.model.Permissions;

import de.deepamehta.core.model.Topic;
import de.deepamehta.core.model.Relation;
import de.deepamehta.core.service.CoreService;
import de.deepamehta.core.service.Plugin;
import de.deepamehta.core.util.JSONHelper;

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.POST;
import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Cookie;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;



@Path("/")
@Consumes("application/json")
@Produces("application/json")
public class AccessControlResource {

    private CoreService dms = Plugin.getService();
    private AccessControlPlugin accessControl = (AccessControlPlugin) dms.getPlugin("de.deepamehta.3-accesscontrol");

    private Logger logger = Logger.getLogger(getClass().getName());

    @POST
    @Path("/topic/{topicId}/owner/{userId}")
    public void setOwner(@PathParam("topicId") long topicId, @PathParam("userId") long userId) {
        accessControl.setOwner(topicId, userId);
    }

    @POST
    @Path("/acl/{topicId}")
    public void createACLEntry(@PathParam("topicId") long topicId, JSONObject aclEntry) throws JSONException {
        Role role = Role.valueOf(aclEntry.getString("role").toUpperCase());
        Permissions permissions = new Permissions(aclEntry.getJSONObject("permissions"));
        accessControl.createACLEntry(topicId, role, permissions);
    }
}
