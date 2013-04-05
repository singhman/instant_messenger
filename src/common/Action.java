package common;

public abstract class Action implements Runnable {

	/* frequency at which action run in millisecond */
	protected final long actionInterval;

	public Action(long interval) {
		// TODO Auto-generated constructor stub
		this.actionInterval = interval;
	}

	public void run() {
		try {
			while (true) {
				Thread.sleep(actionInterval);
				performAction();
			}
		} catch (Exception e) {
			// TODO: don't do anything
		}
	}

	protected abstract void performAction();
}
