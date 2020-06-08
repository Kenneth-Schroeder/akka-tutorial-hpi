package de.hpi.ddm.actors;
import org.apache.commons.lang3.ArrayUtils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.HashSet;
import java.util.LinkedList;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent.CurrentClusterState;
import akka.cluster.ClusterEvent.MemberRemoved;
import akka.cluster.ClusterEvent.MemberUp;
import akka.cluster.Member;
import akka.cluster.MemberStatus;
import de.hpi.ddm.MasterSystem;
import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class Worker extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////
	
	public static final String DEFAULT_NAME = "worker";

	public static Props props() {
		return Props.create(Worker.class);
	}

	public Worker() {
		this.cluster = Cluster.get(this.context().system());
	}
	
	////////////////////
	// Actor Messages //
	////////////////////
        
        @Data @AllArgsConstructor // creates constructors automatically
	public static class hashRangeMessage implements Serializable { // hash all string of length l starting with prefix and using all characters but 'exclude'
                private static final long serialVersionUID = 8343040942748609598L;
                private String universe;
                private String prefix;
                private char exclude;
	}
        
        @Data @AllArgsConstructor
        public static class hashesOfInterestMessage implements Serializable {
                private static final long serialVersionUID = 8343040942748609598L;
                private HashMap<String, LinkedList<Integer>> hashes;
	}
        
        @Data @AllArgsConstructor
        public static class crackPasswordMessage implements Serializable {
                private static final long serialVersionUID = 8343040942748609598L;
                private String hash;
                private String letters;
                private int length;
                private int index;
	}

	/////////////////
	// Actor State //
	/////////////////

	private Member masterSystem;
	private final Cluster cluster;
        private HashMap<String, LinkedList<Integer>> hashesOfInterest;
        
	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);
		
		this.cluster.subscribe(this.self(), MemberUp.class, MemberRemoved.class);
	}

	@Override
	public void postStop() {
		this.cluster.unsubscribe(this.self());
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(CurrentClusterState.class, this::handle)
				.match(MemberUp.class, this::handle)
				.match(MemberRemoved.class, this::handle)
                                 .match(hashRangeMessage.class, this::handle)
                                 .match(hashesOfInterestMessage.class, this::handle)
                                 .match(crackPasswordMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}
        
        private void handle(crackPasswordMessage message){
            // try all combinations of the characters of length x
            
            ArrayList<String> combinations = new ArrayList<String>();
            pickN_withReplacement(message.letters, message.length, combinations);
            
            for(String combination : combinations) {
                if(hash(combination).equals(message.hash)) {
                    this.sender().tell(new Master.foundPasswordMessage(message.index, combination), this.self());
                    break;
                }
            }
            
            this.sender().tell(new Master.idleMessage(), this.self());
        }
        
        private void handle(hashesOfInterestMessage message){
            hashesOfInterest = message.hashes;
            this.sender().tell(new Master.idleMessage(), this.self());
        }
        
        private void handle(hashRangeMessage message) {
		String suffixCharacters = "";
                
                for(char c : message.universe.toCharArray()){
                    if(message.prefix.indexOf(c) == -1){ // character not in prefix, thus can be used for suffix
                        suffixCharacters = suffixCharacters + c;
                    }
                }
                
                char[] possibleCharacters = suffixCharacters.toCharArray();
                possibleCharacters = ArrayUtils.removeElement(possibleCharacters, message.exclude);
                
                ArrayList<String> suffixes = new ArrayList<String>();
                heapPermutation(possibleCharacters, possibleCharacters.length, suffixes, possibleCharacters.length);
                
                for(int i = 0; i < suffixes.size(); i++){
                    String input = message.prefix + suffixes.get(i);
                    String _hash = hash(input);
                    if(hashesOfInterest.containsKey(_hash)){
                        this.sender().tell(new Master.foundHashMessage(input, _hash), this.self());
                    }
                }
                 
                this.log().info("Finished all hints with prefix " + message.prefix + "... that are not using " + message.exclude);
                this.sender().tell(new Master.idleMessage(), this.self());
	}

	private void handle(CurrentClusterState message) { // used to find Master and register to him
		message.getMembers().forEach(member -> {
			if (member.status().equals(MemberStatus.up()))
				this.register(member);
		});
	}

	private void handle(MemberUp message) { 
		this.register(message.member());
	}

	private void register(Member member) { // register to a Master
		if ((this.masterSystem == null) && member.hasRole(MasterSystem.MASTER_ROLE)) {
			this.masterSystem = member;
			
			this.getContext()
				.actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME)
				.tell(new Master.RegistrationMessage(), this.self());
		}
	}
	
	private void handle(MemberRemoved message) { // take poison pill if master was removed
		if (this.masterSystem.equals(message.member()))
			this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
	}
	
	private String hash(String line) { // returns SHA-256 hash of string as string
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashedBytes = digest.digest(String.valueOf(line).getBytes("UTF-8"));
			
			StringBuffer stringBuffer = new StringBuffer();
			for (int i = 0; i < hashedBytes.length; i++) {
				stringBuffer.append(Integer.toString((hashedBytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			return stringBuffer.toString();
		}
		catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	// Generating all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void heapPermutation(char[] a, int size, List<String> l, int len) { // saves all permutations of size 'size' of chars a in l
		// If size is 1, store the obtained permutation
		if (size == a.length-len+1) 
			l.add(new String(a));

		for (int i = 0; i < size; i++) {
			heapPermutation(a, size - 1, l, len);

			// If size is odd, swap first and last element
			if (size % 2 == 1) {
				char temp = a[0];
				a[0] = a[size - 1];
				a[size - 1] = temp;
			}

			// If size is even, swap i-th and last element
			else {
				char temp = a[i];
				a[i] = a[size - 1];
				a[size - 1] = temp;
			}
		}
	}
        
        private void pickN_withReplacement(String options, int len, ArrayList<String> combinations) {
            char[] cc = new char[len];
            _pickN_withReplacement(cc, 0, options.toCharArray(), len, combinations);
        }
        
        private void _pickN_withReplacement(char[] current_combination, int next_idx,  char[] options, int len, ArrayList<String> combinations) {
            if(next_idx == len){
                combinations.add(new String(current_combination));
                return;
            }
            
            for(char c : options){
                current_combination[next_idx] = c;
                _pickN_withReplacement(current_combination, next_idx + 1, options, len, combinations);
            }
        }
}
