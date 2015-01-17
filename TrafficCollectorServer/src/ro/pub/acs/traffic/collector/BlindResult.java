package ro.pub.acs.traffic.collector;

import java.math.BigInteger;

public class BlindResult {
	private BigInteger blind;
	private BigInteger random;

	public BigInteger getBlind() {
		return blind;
	}

	public void setBlind(BigInteger blind) {
		this.blind = blind;
	}

	public BigInteger getRandom() {
		return random;
	}

	public void setRandom(BigInteger random) {
		this.random = random;
	}
}
