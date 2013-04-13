package server;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Iterator;

import common.PruneAction;

public class OnlineUsers {
	/*
	 * The interval in milliseconds in which the job to prune logged in users
	 * is run. If a user has not pinged the server within the last
	 * <code>LOGOUT_USER_JOB_INTERVAL</code> milliseconds they will be logged 
	 * out.  Note that due to the way this job is run, a user can potentially
	 * be logged in for twice this time.
	 */
	public static final int LOGOUT_USER_JOB_INTERVAL = 3 * 60 * 1000; // 3 minutes
	
	private final ConcurrentHashMap<UUID, User> users = 
		new ConcurrentHashMap<UUID, User>();
	private String userListCache = "";
	private static boolean regenerateCache = false;
	
	public OnlineUsers() {
		new Thread(new LogoutUserJob()).start();
	}
	
	public String getUsers(){
		synchronized (users) {
			if(regenerateCache){
				regenerateUserListCache();
				regenerateCache = false;
			}
		}
		return userListCache;
	}
	
	public boolean isOnline(UUID userId){
		return this.users.containsKey(userId);
	}
	
	public boolean isOnline(String username) {
		if(this.users == null){
			return false;
		}
		
		for (User user : this.users.values()) {
			if (user.getUsername().equals(username)) {
				return true;
			}
		}
		return false;
	}
	
	public boolean isOnline(int port, InetAddress ip) {
		if(this.users == null){
			return false;
		}
		
		for (User user : this.users.values()) {
			if (user.getUserPort() == port && user.getUserIp().equals(ip)) {
				return true;
			}
		}
		return false;
	}
	
	public User getUser(UUID userId){
		return users.get(userId);
	}
	
	public User getUser(String userName){
		if(this.users == null){
			return null;
		}
		
		for (User user : this.users.values()) {
			if (user.getUsername().equals(userName)) {
				return user;
			}
		}
		
		return null;
	}
	
	public void addUser(UUID userId, User user){
		if(userId == null){
			throw new IllegalArgumentException("id not set on user");
		}
		
		synchronized (users) {
			if(!users.containsKey(userId)){
				users.put(userId, user);
			}
			regenerateUserListCache();
		}
	}
	
	public void removeUser(UUID id){
		User user = null;
		synchronized (users) {	
			if(!users.contains(id)){
				user = users.remove(id);
			}
			if(user != null){
				regenerateUserListCache();
				user.setLastPinged(-1);
				user.destroySessionKey();
				user.setUserId(null);
			}
		}
	}
	
	public void regenerateUserListCache(){
		final StringBuilder userList = new StringBuilder();
		final ArrayList<String> usernames = new ArrayList<String>();
		
		for(User user: users.values()){
			usernames.add(user.getUsername());
		}
		
		Collections.sort(usernames);
		final Iterator<String> usernameIterator = usernames.iterator();
		
		while(usernameIterator.hasNext()){
			userList.append(usernameIterator.next());
			
			if (usernameIterator.hasNext()) {
				userList.append(",");
			}
		}
		
		userListCache = userList.toString();
	}
	
	/*
	 * Job to logout users who haven't pinged the server in the last
	 * <code>LoggedInUsers.LOGOUT_USER_JOB_INTERVAL</code> milliseconds.
	 * 
	 * @see LoggedInUsers#LOGOUT_USER_JOB_INTERVAL
	 */
	private class LogoutUserJob extends PruneAction<UUID, User> {
		
		public LogoutUserJob(){
			super(LOGOUT_USER_JOB_INTERVAL, users);
		}
		@Override
		protected boolean isPrunable(User object, long pruneBefore){
			final boolean logout = object.getLastPinged() <= pruneBefore;
			
			if(logout){
				object.setLastPinged(-1);
				object.destroySessionKey();
				object.setUserId(null);
				System.out.println("Logged out " + object.getUsername() + 
						" for expired ping");
					regenerateCache = true;
			}
			
			return logout;
		}
	}
}
