package org.dcache.auth;

import java.security.Principal;
import java.util.NoSuchElementException;
import java.util.Set;

import javax.security.auth.Subject;

/**
 * This class is a copy of dCache's Subjects class with changes to use
 * SUNs internal classes.
 *
 * FIXME: have to be replaced by dCache's implementation.
 */
public class Subjects
{
    /**
     * The subject representing the root user, that is, a user that is
     * empowered to do everything.
     */
    public static final Subject ROOT;
    public static final Subject NOBODY;

    static {
        ROOT = new Subject();
        ROOT.getPrincipals().add(new UidPrincipal(0));
        ROOT.getPrincipals().add(new GidPrincipal(0, true));
        ROOT.setReadOnly();

        NOBODY = new Subject();
        NOBODY.setReadOnly();
    }

    /**
     * Returns true if and only if the subject is root, that is, has
     * the user ID 0.
     */
    public static boolean isRoot(Subject subject) {
        return hasUid(subject, 0);
    }

    /**
     * Returns true if and only if the subject is nobody, i.e., does
     * not have a UID.
     *
     * Being nobody does not imply that the user is anonymous: The
     * subject's identity may have been established through some
     * authentication mechanism. However the subject could not be
     * assigned an internal identity in dCache.
     */
    public static boolean isNobody(Subject subject) {
        for (Principal principal: subject.getPrincipals()) {
            if (principal instanceof UidPrincipal) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns true if and only if the subject has the given user ID.
     */
    public static boolean hasUid(Subject subject, long uid) {
        Set<UidPrincipal> principals =
                subject.getPrincipals(UidPrincipal.class);
        for (UidPrincipal principal : principals) {
            if (principal.getUid() == uid) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true if and only if the subject has the given group ID.
     */
    public static boolean hasGid(Subject subject, long gid) {
        Set<GidPrincipal> principals =
                subject.getPrincipals(GidPrincipal.class);
        for (GidPrincipal principal : principals) {
            if (principal.getGid() == gid) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the users IDs of a subject.
     */
    public static long[] getUids(Subject subject) {
        Set<UidPrincipal> principals =
                subject.getPrincipals(UidPrincipal.class);
        long[] uids = new long[principals.size()];
        int i = 0;
        for (UidPrincipal principal : principals) {
            uids[i++] = principal.getUid();
        }
        return uids;
    }

    /**
     * Returns the principal of the given type of the subject. Returns
     * null if there is no such principal.
     *
     * @throw IllegalArguemntException is subject has more than one such principal
     */
    private static <T> T getUniquePrincipal(Subject subject, Class<T> type)
        throws IllegalArgumentException
    {
        T result = null;

        if( subject == null) {
            return null;
        }

        for (Principal principal: subject.getPrincipals()) {
            if (type.isInstance(principal)) {
                if (result != null) {
                    throw new IllegalArgumentException("Subject has multiple principals of type " + type.getSimpleName());
                }
                result = type.cast(principal);
            }
        }
        return result;
    }

    /**
     * Returns the UID of a subject.
     *
     * @throws NoSuchElementException if subject has no UID
     * @throws IllegalArgumentException is subject has more than one UID
     */
    public static long getUid(Subject subject) throws IllegalArgumentException
    {
        UidPrincipal uid = getUniquePrincipal(subject, UidPrincipal.class);
        if (uid == null) {
            return -1;
        }
        return uid.getUid();
    }

    /**
     * Returns the group IDs of a subject. If the user has a primary
     * group, then first element will be a primary group ID.
     */
    public static long[] getGids(Subject subject) {
        Set<GidPrincipal> principals =
                subject.getPrincipals(GidPrincipal.class);
        long[] gids = new long[principals.size()];
        int i = 0;
        for (GidPrincipal principal : principals) {
            if (principal.isPrimaryGroup()) {
                gids[i++] = gids[0];
                gids[0] = principal.getGid();
            } else {
                gids[i++] = principal.getGid();
            }
        }
        return gids;
    }

    /**
     * Returns the primary group ID of a subject.
     *
     * @throws NoSuchElementException if subject has no primary GID
     * @throws IllegalArgumentException if subject has several primary GID
     */
    public static long getPrimaryGid(Subject subject)
        throws NoSuchElementException, IllegalArgumentException
    {
        Set<GidPrincipal> principals =
                subject.getPrincipals(GidPrincipal.class);
        int counter = 0;
        long gid = 0;
        for (GidPrincipal principal : principals) {
            if (principal.isPrimaryGroup()) {
                gid = principal.getGid();
                counter++;
            }
        }

        if (counter == 0) {
            throw new NoSuchElementException("Subject has no primary GID");
        }
        if (counter > 1) {
            throw new IllegalArgumentException("Subject has multiple primary GIDs");
        }

        return gid;
    }

    /**
     * Create a subject for UNIX based user record.
     *
     * @param uid
     * @param gid
     * @param gids
     */
    public static Subject of(int uid, int gid, int...gids) {

        Subject subject = new Subject();
        subject.getPrincipals().add(new UidPrincipal(uid));
        subject.getPrincipals().add(new GidPrincipal(gid, true));
        for (int g : gids) {
            subject.getPrincipals().add(new GidPrincipal(g, false));
        }
        return subject;
    }
}
