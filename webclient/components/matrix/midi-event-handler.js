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
    
    currentMeasureTime: 0,
    perLine: -1,
    
    init: function () {
        MIDI.loadPlugin({
            soundfontUrl: "./soundfont/",
            instrument: "acoustic_grand_piano",
            callback: function () {
                /*
                var delay = 0; // play one note every quarter second
                var note = 50; // the MIDI note
                var velocity = 127; // how hard the note hits
                // play the note
                MIDI.setVolume(0, 127);
                MIDI.noteOn(0, note, velocity, delay);
                MIDI.noteOff(0, note, delay + 0.75);
                */
            }
        });
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
    
    handleEvent: function(event) {
        
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
            this.notesON[vexNote] = parseInt(event.content.midi_ts);
        }
        else if (this.notesON[vexNote])
        {
            // How long the note last
            var duration = parseInt(event.content.midi_ts) - this.notesON[vexNote];
            delete this.notesON[vexNote];
            
            var fraction =  duration / this.beat;
            
            console.log(fraction);
            
            var musicFraction;

           
           var duration = Math.floor(Math.log2(1 / fraction)) - 1;
            switch (duration) {
                case 4:
                    musicFraction = "w";
                    break;
                case 2:
                    musicFraction = "h";
                    break;
                case 1:
                    musicFraction = "q";
                    break;
                case 0:
                    musicFraction = "8";
                    break;
                case -1:
                    musicFraction = "16";
                    break;
                case -2:
                    musicFraction = "32";
                    break;

            }
            this.currentMeasureTime += duration;

            
            vexNote = ":" + musicFraction + " " + vexNote;
            
            this.addNote(vexNote);
        }
    },
    
    c: function(fraction) {
        return Math.floor(Math.log2(1 / fraction)) - 1;
        
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
