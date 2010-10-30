package de.deepamehta.plugins.accesscontrol;

import de.deepamehta.core.model.DataField;
import de.deepamehta.core.model.Topic;
import de.deepamehta.core.model.TopicType;
import de.deepamehta.core.service.Plugin;
import de.deepamehta.core.util.JavaUtils;

import java.util.Date;
import java.util.HashMap;
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

    // ------------------------------------------------------------------------------------------------- Private Methods

    private Topic getUser(String username) {
        return dms.getTopic("de/deepamehta/core/property/username", username);
    }

    private String encryptPassword(String password) {
        return ENCRYPTED_PASSWORD_PREFIX + JavaUtils.encodeSHA256(password);
    }
}
