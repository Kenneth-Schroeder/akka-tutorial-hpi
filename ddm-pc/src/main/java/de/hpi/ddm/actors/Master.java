package de.hpi.ddm.actors;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashSet;
import java.util.Queue;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.actor.Terminated;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.ArrayUtils;

public class Master extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////
	
	public static final String DEFAULT_NAME = "master";

	public static Props props(final ActorRef reader, final ActorRef collector) {
		return Props.create(Master.class, () -> new Master(reader, collector));
	}

	public Master(final ActorRef reader, final ActorRef collector) {
		this.reader = reader;
		this.collector = collector;
		this.workers = new ArrayList<>();
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data
	public static class StartMessage implements Serializable {
		private static final long serialVersionUID = -50374816448627600L;
	}
	
	@Data @NoArgsConstructor @AllArgsConstructor
	public static class BatchMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private List<String[]> lines;
	}

	@Data
	public static class RegistrationMessage implements Serializable {
		private static final long serialVersionUID = 3303081601659723997L;
	}
        
        @Data
	public static class idleMessage implements Serializable {
		private static final long serialVersionUID = 3303081601659723997L;
	}
        
        @Data @AllArgsConstructor
	public static class foundHashMessage implements Serializable {
                private static final long serialVersionUID = 3303081601659723997L;
                private String input;
                private String hash;
	}
        
        @Data @AllArgsConstructor
	public static class foundPasswordMessage implements Serializable {
                private static final long serialVersionUID = 3303081601659723997L;
                private int index;
                private String password;
	}
	
	/////////////////
	// Actor State //
	/////////////////

	private final ActorRef reader;
	private final ActorRef collector;
	private final List<ActorRef> workers;
        
        private ArrayList<Integer> pw_ready_indices = new ArrayList<Integer>();     // indizes of passwords of which all hints have been solved
        private int pw_task_counter = 0;                                            // keeps track of which pw_ready_indices have been assigned to be solved already
        private ArrayList<String> passwordCharOptions = new ArrayList<String>();    // character universe for each password
        private ArrayList<String> passwordHashes = new ArrayList<String>();         // hashes of the passwords
        private int passwordLength = 10;                                            // length of each password (single integer cuz' supposed to be the same across all passwords)
        private ArrayList<Integer> numberOfSolvedHints = new ArrayList<Integer>();  // counters to keep track of how many hints have been solved
        private ArrayList<String> solvedPasswords = new ArrayList<String>();        // all the plaintext passwords
        private int solved_pw_counter = 0;                                          // counter for checking if all passwords are solved
        
        private ArrayList<ArrayList<String>> hintHashes = new ArrayList<ArrayList<String>>();   // all the hints in hash format
        private HashMap<String, LinkedList<Integer>> hashesOfInterest = new HashMap<String, LinkedList<Integer>>(); // all the hints in hash format in hashMap form for easy lookup
        
        ArrayList<String> prefixes = new ArrayList<String>();   // list of prefixes of all the possible plaintext hints that need to be tried
        private int prefixCounter = 0;                          // counter to keep track which prefixes have been distributed to workers to be solved already
        
	private long startTime;
        private boolean finishedReading = false;
        
        private Queue<ActorRef> idle_workers = new LinkedList<ActorRef>();  // queue of idle workers that couldn't be given new task immediately
	
	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(StartMessage.class, this::handle)
				.match(BatchMessage.class, this::handle)
				.match(Terminated.class, this::handle)
				.match(RegistrationMessage.class, this::handle)
                                 .match(idleMessage.class, this::handle)
                                 .match(foundHashMessage.class, this::handle)
                                 .match(foundPasswordMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}
        
        int counter = 0;
        protected void handle(foundHashMessage message){
            // remove char from possible chars of corresponding pw
            if(++counter % 50 == 0)
                this.log().info("Found " + counter + " hint hashes");
            
            HashSet<Character> hint_possible_chars = new HashSet<Character>();
            for(char c : message.input.toCharArray()){
                hint_possible_chars.add(c);
            }
            
            // which row(s) is the hash coming from?? use hashmap instead of hashset and point to list of indices  DONE
            // update possible chars at those rows
            for(Integer row_idx : hashesOfInterest.get(message.hash)){ // iterate over the rows containing this hash
                numberOfSolvedHints.set(row_idx, numberOfSolvedHints.get(row_idx)+1);
                        
                HashSet<Character> remaining_possible_chars = new HashSet<Character>();
                for(char c : passwordCharOptions.get(row_idx).toCharArray()){
                    remaining_possible_chars.add(c);
                }
                
                remaining_possible_chars.retainAll(hint_possible_chars);
                
                StringBuilder result = new StringBuilder();
                for(char c : remaining_possible_chars){
                    result.append(c);
                }
                
                passwordCharOptions.set(row_idx, result.toString());
                
                if(numberOfSolvedHints.get(row_idx) == hintHashes.get(row_idx).size()){
                    // add idx to solvable pws
                    pw_ready_indices.add(row_idx);
                    
                    // send to idle worker if any
                    trySendingPwTask();
                }
            }
            
            
            // if all hints of pw are solved, queue possible pw cracking task
            // if worker is idle, send him this task
        }
        
        protected void handle(foundPasswordMessage message) {
            solvedPasswords.set(message.index, message.password);
            this.collector.tell(new Collector.CollectMessage("Password of user " + (message.index+1) + " is " + message.password), reader);
            
            if(++solved_pw_counter == solvedPasswords.size()){
                this.collector.tell(new Collector.PrintMessage(), this.self());
                this.terminate();
            }
            this.log().info("Found " + solved_pw_counter + "/" + solvedPasswords.size() + " passwords");
        }
        
        
        protected void handle(idleMessage message) {
		sendWork();
	}

	protected void handle(StartMessage message) {
		this.startTime = System.currentTimeMillis();
		this.reader.tell(new Reader.ReadMessage(), this.self());
	}
	
	protected void handle(BatchMessage message) { // receiving a batch of input data from Reader
		
		///////////////////////////////////////////////////////////////////////////////////////////////////////
		// The input file is read in batches for two reasons: /////////////////////////////////////////////////
		// 1. If we distribute the batches early, we might not need to hold the entire input data in memory. //
		// 2. If we process the batches early, we can achieve latency hiding. /////////////////////////////////
		// TODO: Implement the processing of the data for the concrete assignment. ////////////////////////////
		///////////////////////////////////////////////////////////////////////////////////////////////////////
                
		if (message.getLines().isEmpty()) { // if nothing new is read tell the Collector to print the results
                        this.log().info("Began prefix calculation...");
                        pickN_fromSet(passwordCharOptions.get(0), 2, prefixes);
                        this.log().info("Finished prefix calculation! " + prefixes.size());
                    
                    
                        for(int i = 0; i < hintHashes.size(); i++) { // ArrayList<String> line : hintHashes){
                            for(String hash : hintHashes.get(i)){
                                LinkedList<Integer> temp = new LinkedList<Integer>();
                                
                                if(hashesOfInterest.containsKey(hash)){
                                    temp = hashesOfInterest.get(hash);
                                }
                                
                                temp.add(i);
                                
                                hashesOfInterest.put(hash, temp);
                            }
                        }
                        finishedReading = true;
                        
                        for(ActorRef worker : this.workers){
                            worker.tell(new Worker.hashesOfInterestMessage(hashesOfInterest), this.self());
                        }
                        
			// this.collector.tell(new Collector.PrintMessage(), this.self());
			// this.terminate();
			return;
		}
                
		
		for (String[] line : message.getLines()) {
                        passwordHashes.add(line[4]);
                        passwordCharOptions.add(line[2]);
                        passwordLength = Integer.parseInt(line[3]);
                        numberOfSolvedHints.add(0);
                        solvedPasswords.add("");
                                
                        ArrayList<String> hints = new ArrayList<String>();
                        
                        for(int i = 5; i < line.length; i++){
                            hints.add(line[i]);
                        }
                        hintHashes.add(hints);
                        
                        System.out.println(Arrays.toString(line)); // output what is received
                }
                
                // master needs to wait for workers -> NO, there will already be some local workers once this function is started, assign range to worker once he registers to master
                // then extract all the hint hashes from this message
                // create workers? no, they will join  maybe;
                // assign each worker a range to work on
                // start asking for results
                
                
		
		this.collector.tell(new Collector.CollectMessage("Processed batch of size " + message.getLines().size()), this.self());
		this.reader.tell(new Reader.ReadMessage(), this.self()); // tell the reader to read more
	}
	
	protected void terminate() {
		this.reader.tell(PoisonPill.getInstance(), ActorRef.noSender());
		this.collector.tell(PoisonPill.getInstance(), ActorRef.noSender());
		
		for (ActorRef worker : this.workers) {
			this.context().unwatch(worker);
			worker.tell(PoisonPill.getInstance(), ActorRef.noSender());
		}
		
		this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
		
		long executionTime = System.currentTimeMillis() - this.startTime;
		this.log().info("Algorithm finished in {} ms", executionTime);
	}

	protected void handle(RegistrationMessage message) { // watching worker that registers
                System.out.println("WORKER REGISTERED!");
                this.context().watch(this.sender());
                this.workers.add(this.sender());
                
                if(finishedReading){
                    this.sender().tell(new Worker.hashesOfInterestMessage(hashesOfInterest), this.self());
                }
                // sendWork();
                
//		this.log().info("Registered {}", this.sender());
	}
	
	protected void handle(Terminated message) { // remove actor that terminated
		this.context().unwatch(message.getActor());
		this.workers.remove(message.getActor());
//		this.log().info("Unregistered {}", message.getActor());
	}
        
        protected void sendWork(){
            if(prefixCounter == prefixes.size()){
                System.out.println("All prefixes distributed!");
                idle_workers.add(this.sender());
                trySendingPwTask();
                return;
            }
            
            String nextPrefix = prefixes.get(prefixCounter++);
            char nextExclude = nextPrefix.charAt(nextPrefix.length() - 1);
            nextPrefix = nextPrefix.substring(0, nextPrefix.length() - 1);
            
            this.sender().tell(new Worker.hashRangeMessage(passwordCharOptions.get(0), nextPrefix, nextExclude), this.self()); // NOTE: passwords character options hardcoded to first entry since it's supposed to be the same for all rows
        }
        
        protected void trySendingPwTask(){ // TODO also keep track of idle workers if we have nothing to send immediately
            if(pw_task_counter < pw_ready_indices.size()){
                int row_idx = pw_ready_indices.get(pw_task_counter);
                
                // build message
                if(!idle_workers.isEmpty()){
                    idle_workers.poll().tell(new Worker.crackPasswordMessage(passwordHashes.get(row_idx), passwordCharOptions.get(row_idx), passwordLength, row_idx), this.self());
                    pw_task_counter++;
                }
            }
        }
        
        protected void pickN_fromSet(String options, int len, List<String> results) {
            char[] helper = new char[len];
            boolean[] unused = new boolean[options.length()];
            java.util.Arrays.fill(unused, true);
            _pickN_fromSet(helper, unused, 0, options, results);
        }
        
        protected void _pickN_fromSet(char[] perm, boolean[] unused, int pos, String options, List<String> results) {
            if (pos == perm.length) {
                results.add(new String(perm));
            } 
            else {
                for (int i = 0 ; i < options.length() ; i++) {
                    if(unused[i]){
                        perm[pos] = options.charAt(i);
                        unused[i] = false;
                        _pickN_fromSet(perm, unused, pos+1, options, results);
                        unused[i] = true; // make sure when resolving recursion we are cleaning up for following steps
                    }
                }
            }
        }
}
