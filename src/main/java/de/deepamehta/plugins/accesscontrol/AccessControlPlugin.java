package de.deepamehta.plugins.accesscontrol;

import de.deepamehta.core.model.DataField;
import de.deepamehta.core.model.RelatedTopic;
import de.deepamehta.core.model.Topic;
import de.deepamehta.core.model.TopicType;
import de.deepamehta.core.service.Plugin;
import de.deepamehta.core.util.JavaUtils;

import static java.util.Arrays.asList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;



public class AccessControlPlugin extends Plugin {

    private static final String DEFAULT_USER = "admin";
    private static final String DEFAULT_PASSWORD = "";
    private static final String ENCRYPTED_PASSWORD_PREFIX = "-SHA256-";  // don't change this

    // ---------------------------------------------------------------------------------------------- Instance Variables

    private Logger logger = Logger.getLogger(getClass().getName());

    // -------------------------------------------------------------------------------------------------- Public Methods



    // ************************
    // *** Overriding Hooks ***
    // ************************



    @Override
    public void evokePluginHook() {
        Map properties = new HashMap();
        properties.put("de/deepamehta/core/property/username", DEFAULT_USER);
        properties.put("de/deepamehta/core/property/password", encryptPassword(DEFAULT_PASSWORD));
        dms.createTopic("de/deepamehta/core/topictype/user", properties, null);     // clientContext=null
    }

    // Note: we must use the postCreateHook to create the relation because at pre_create the document has no ID yet.
    @Override
    public void postCreateHook(Topic topic, Map<String, String> clientContext) {
        // check precondition 1
        if (clientContext == null) {
            logger.warning(topic + " can't be related to a user because current user is unknown " +
                "(client context is not initialzed)");
            return;
        }
        // check precondition 2
        String username = clientContext.get("username");
        if (username == null) {
            logger.warning(topic + " can't be related to a user because current user is unknown " +
                "(no setting found in client context)");
            return;
        }
        // check precondition 3
        Topic user = getUser(username);
        if (user == null) {
            logger.warning(topic + " can't be related to a user because user \"" + username + "\" doesn't exist");
            return;
        }
        // check precondition 4
        if (topic.id == user.id) {
            logger.warning(topic + " can't be related to user \"" + username +
                "\" because the topic is the user itself!");
            return;
        }
        // relate topic to workspace
        dms.createRelation("CREATOR", topic.id, user.id, null);
    }

    @Override
    public void preUpdateHook(Topic topic, Map<String, Object> newProperties) {
        // encrypt password of new users
        if (topic.typeUri.equals("de/deepamehta/core/topictype/user")) {
            // we recognize a new user (or changed password) if password doesn't begin with ENCRYPTED_PASSWORD_PREFIX
            String password = (String) newProperties.get("de/deepamehta/core/property/password");
            if (!password.startsWith(ENCRYPTED_PASSWORD_PREFIX)) {
                newProperties.put("de/deepamehta/core/property/password", encryptPassword(password));
            }
        }
    }

    /**
     * Adds "Creator" data field to all topic types.
     */
    @Override
    public void modifyTopicTypeHook(TopicType topicType) {
        //
        DataField creatorField = new DataField("Creator", "reference");
        creatorField.setUri("de/deepamehta/core/property/creator");
        creatorField.setRelatedTypeUri("de/deepamehta/core/topictype/user");
        creatorField.setEditor("checkboxes");
        //
        topicType.addDataField(creatorField);
    }

    @Override
    public void provideAuxiliaryHook(Topic topic, Map<String, String> clientContext) {
        Topic user = getUser(clientContext);
        Topic creator = getCreator(topic.id);
        //
        boolean writePermission = user != null && creator != null && user.id == creator.id;
        //
        Map acl = new HashMap();
        acl.put("write", writePermission);
        topic.setAuxiliary("permissions", acl);
    }

    // ------------------------------------------------------------------------------------------------- Private Methods

    /**
     * Returns the user that is represented by the client context, or <code>null</code> if no user is logged in.
     */
    private Topic getUser(Map<String, String> clientContext) {
        if (clientContext == null) {    // some callers to dms.getTopic() doesn't pass a client context
            return null;
        }
        String username = clientContext.get("username");
        if (username == null) {
            return null;
        }
        return getUser(username);
    }

    /**
     * Returns the user (topic) by username, or <code>null</code> if no such user exists.
     */
    private Topic getUser(String username) {
        return dms.getTopic("de/deepamehta/core/property/username", username);
    }

    // ---

    /**
     * Returns the creator (a user topic) of a topic, or <code>null</code> if no creator exists.
     */
    private Topic getCreator(long topicId) {
        List<RelatedTopic> users = dms.getRelatedTopics(topicId,
            asList("de/deepamehta/core/topictype/user"),
            asList("CREATOR;INCOMING"), null);
        //
        if (users.size() == 0) {
            return null;
        } else if (users.size() > 1) {
            throw new RuntimeException("Ambiguity: topic " + topicId + " has " + users.size() + " creators");
        }
        //
        return users.get(0).getTopic();
    }

    // ---

    private String encryptPassword(String password) {
        return ENCRYPTED_PASSWORD_PREFIX + JavaUtils.encodeSHA256(password);
    }
}
