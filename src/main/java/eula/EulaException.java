package eula;

public class EulaException extends Exception {
	public EulaException(String message){
		super(message);
	}

	public EulaException(String message, Throwable cause){
		super(message, cause);
	}

	public EulaException(Throwable cause){
		super(cause);
	}

	public EulaException(){
		super();
	}

}