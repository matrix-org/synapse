/*
 Copyright 2014 matrix.org
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

String.prototype.endsWith = function(suffix) {
    return this.indexOf(suffix, this.length - suffix.length) !== -1;
};

var MidiEventHandler = {
    midiQueue: [],
    
    startTime: 0,
    
    vexTabString: "",
    
    chord: {
        start_midi_ts: 0,
        end_midi_ts: 0,
        notes: {},
    },
    
    currentMeasureTime: 0,
    perLine: -1,
    
    pastMidiEventsInWrongOrder: [],
    
    init: function (eventHandlerService) {
        
        // During initialSync, handleEvent is called for each event from latest events to the past.
        // Need to reorder them.
        var self = this;
        eventHandlerService.waitForInitialSyncCompletion().then(
            function() {
                for (var i = self.pastMidiEventsInWrongOrder.length - 1; i >= 0; i--) {
                    self.handleEvent(self.pastMidiEventsInWrongOrder[i], true);
                }
            }
        );
    },
    
    reset: function() {
        
        this.vexTabString = "";
        this.currentMeasureTime = 0;
        this.perLine = -1;
        this.ready = false;
        
        this.beat = 0;
        this.intial4Timings = [];

        this.renderer = new Vex.Flow.Renderer($('#boo')[0],
        Vex.Flow.Renderer.Backends.CANVAS);

        this.artist = new Vex.Flow.Artist(10, 10, 750, {scale: 0.8});
        this.vextab = new Vex.Flow.VexTab(this.artist);
        
        // key is the note string, value its midi_ts value when it went to ON
        this.notesON = {};
    },

/*
        vextab.parse("tabstave notation=true tablature=false \n\
notes 4-5-6/3 ## =|: 5-4-2/3 2/2 =:|\n\
\n\
tabstave notation=true tablature=false\n\
notes C-D-E/4 #0# =:: C-D-E-F/4 =|=");
        artist.render(renderer);
        */


    setReady: function() {
        this.ready = true;
        this.render();
    },
    
    getLogDuration: function(duration) {
        var fraction =  duration / this.beat;
        //console.log(fraction);

        // log2(4) = 2  # 4 beats == whole bar == w
        // log2(2) = 1  # 2 beats == half = h
        // log2(1) = 0

        return Math.ceil(Math.log2(fraction));
    },
    
    renderChord: function(duration, rest) {
        var musicFraction;
        var logDuration = this.getLogDuration(duration);
        var trashIt = false; // Flag to ignore artefact(???)
        switch (logDuration) {
            case 2:
                musicFraction = "w";
                break;
            case 1:
                musicFraction = "h";
                break;
            case 0:
                musicFraction = "q";
                break;
          // quantise to quavers for now
            case -1:
                musicFraction = "8";
                break;
            case -2:
                musicFraction = "16";
                break;
            case -3:
                musicFraction = "32";
                break;

            default:
                console.log("## Ignored note");
                // Too short, ignore it
                trashIt = true;
                break;
        }

        // Matthew is about to fix it 
        if (trashIt) return;
        
        this.currentMeasureTime += duration / this.beat;

        var s = ":" + musicFraction + " ";
        
        if (rest) {
            s += "##";
        }
        else {
            var notes = [];
            for (var note in this.chord.notes) {
                if (this.chord.notes.hasOwnProperty(note)) {
                    notes.push(note);
                }
            }
        
            if (notes.length > 1) {
                s += "(";
                for (var i = 0; i < notes.length; i++) {
                    s += notes[i];
                    if (i < notes.length - 1) s+= ".";
                }
                s += ")";
            }
            else {
                s += notes[0];
            }
        }
        
        this.addNote(s);        
    },
    
    handleEvent: function(event, isLiveEvent) {
        
        if(!isLiveEvent) {
            this.pastMidiEventsInWrongOrder.push(event);
            return;
        }
        
        if (0 === this.beat)
        {
            // We do not know the beat yeat
            // Wait for 4 notes to compute the tempo
            if ("on" === event.content.state) {
                
                this.intial4Timings.push(parseInt(event.content.midi_ts));
                
                if (4 === this.intial4Timings.length) {
                    // un beat: duree d'un temps
                    this.beat = (this.intial4Timings[3] - this.intial4Timings[0]) / 3;
                    
                    console.log("## beat: " + this.beat);
                }
            }
            
            return;
        }
        
        var vexNote = this.getVexNote( this.getMidiNote(event.content.note) );

        if ("on" === event.content.state) {
            var midi_ts = parseInt(event.content.midi_ts);
            this.notesON[vexNote] = midi_ts;
            
            if (event.content.midi_ts - this.chord.start_midi_ts < 300) { // empirically
                // just add it to the current chord we're building up.
                this.chord.notes[vexNote]++;
            }
            else {
                // render the last note/chord
                this.renderChord(this.chord.end_midi_ts - this.chord.start_midi_ts, false);

                // check if it's been so long since the last note that we should do a rest.
                var logDuration = this.getLogDuration(midi_ts - this.chord.end_midi_ts);
                
                //console.log((midi_ts - this.chord.end_midi_ts) + " -> " + logDuration);
                
                if (logDuration >= 1) {
                    this.renderChord(midi_ts - this.chord.end_midi_ts, true);
                }
                                
                // start a new chord
                this.chord.notes = {};
                this.chord.notes[vexNote]++;
                this.chord.start_midi_ts = midi_ts;
                this.chord.end_midi_ts = 0;
            }
        }
        else if (this.notesON[vexNote]) // note is turning off.
        {
            // How long the note lasts
            this.chord.end_midi_ts = parseInt(event.content.midi_ts);
            delete this.notesON[vexNote];
            
            // TODO: optimisation: we could render this note now if we know there are no others sounding...
        }
    },
            
    addNote: function (vexNote) {
        
        if (-1 === this.perLine)
        {
            // Create a new line
            if ("" !== this.vexTabString) {
                // Add a line break with the previous line
                this.vexTabString += "\n";
            }
            this.vexTabString += "tabstave notation=true tablature=false clef=treble time=C\nnotes ";
            this.perLine = 0;
        }
        
        this.vexTabString += vexNote;

        console.log(this.currentMeasureTime);
        if (this.currentMeasureTime >= 4) {
            
            this.perLine = this.perLine + 1;
            
            if (this.perLine <= 3) {
                this.vexTabString += " | ";
            }
            else {
                // Break the line
                this.vexTabString += "\n";
                this.perLine = -1;
            }
            
            this.currentMeasureTime = 0;

        }
        else {
            this.vexTabString += " ";
        }
        
        if (this.ready) {
            this.render();
        }
        
    },
    
    getVexNote: function(midiNote) {
        
            return midiNote;

        // TODO: manage this
        var vexNote;
        if (2 === midiNote.length) {
            
            if (this.vexTabString.endsWith('#')) {
                vexNote = midiNote[0] + 'n/' + midiNote[1];
            }
            else
            {
                vexNote = midiNote[0] + '/' + midiNote[1];
            }
        }
        
        return vexNote;
    },
    
    getMidiNote: function(midiNoteNumber) {
        var noteString = [ "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B" ];
        var octave = Math.floor(midiNoteNumber / 12) - 1;
        var noteIndex = (midiNoteNumber % 12);
        return noteString[noteIndex] + "/" + octave;
    },
    
    render: function() {
        
        console.log("####\n" + this.vexTabString);
        
        this.vextab.reset();
        this.artist.reset();
          
        this.vextab.parse(this.vexTabString);
        this.artist.render(this.renderer);
    }
    
};
