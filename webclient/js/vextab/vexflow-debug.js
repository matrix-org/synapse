/**
 * VexFlow Engraver 1.2 Custom
 * A library for rendering musical notation and guitar tablature in HTML5.
 *
 *                    http://www.vexflow.com
 *
 * Copyright (c) 2010 Mohit Muthanna Cheppudira <mohit@muthanna.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * This library makes use of Simon Tatham's awesome font - Gonville.
 *
 * Build ID: 0xFE@4af446259300db66856c51b1face77457796ab5f
 * Build date: 2014-05-01 12:29:38 -0400
 */
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// This file implements utility methods used by the rest of the VexFlow
// codebase.
//
// ## JSHint Settings
//
/* global window: false */
/* global document: false */

function Vex() {}

// Default log function sends all arguments to console.
Vex.L = function(block, args) {
  if (!args) return;
  var line = Array.prototype.slice.call(args).join(" ");
  window.console.log(block + ": " + line);
};

// Default runtime exception.
Vex.RuntimeError = function(code, message) {
  this.code = code;
  this.message = message;
};
Vex.RuntimeError.prototype.toString = function() {
  return "RuntimeError: " + this.message;
};

// Shortcut method for `RuntimeError`.
Vex.RERR = Vex.RuntimeError;

// Merge `destination` hash with `source` hash, overwriting like keys
// in `source` if necessary.
Vex.Merge = function(destination, source) {
  for (var property in source)
    destination[property] = source[property];
  return destination;
};

// DEPRECATED. Use `Math.min`.
Vex.Min = function(a, b) {
  return (a > b) ? b : a;
};

// DEPRECATED. Use `Math.max`.
Vex.Max = function(a, b) {
  return (a > b) ? a : b;
};

// Round number to nearest fractional value (`.5`, `.25`, etc.)
Vex.RoundN = function(x, n) {
  return (x % n) >= (n/2) ?
    parseInt(x / n, 10) * n + n : parseInt(x / n, 10) * n;
};

// Locate the mid point between stave lines. Returns a fractional line if a space.
Vex.MidLine = function(a, b) {
  var mid_line = b + (a - b) / 2;
  if (mid_line % 2 > 0) {
    mid_line = Vex.RoundN(mid_line * 10, 5) / 10;
  }
  return mid_line;
};

// Take `arr` and return a new list consisting of the sorted, unique,
// contents of arr. Does not modify `arr`.
Vex.SortAndUnique = function(arr, cmp, eq) {
  if (arr.length > 1) {
    var newArr = [];
    var last;
    arr.sort(cmp);

    for (var i = 0; i < arr.length; ++i) {
      if (i === 0 || !eq(arr[i], last)) {
        newArr.push(arr[i]);
      }
      last = arr[i];
    }

    return newArr;
  } else {
    return arr;
  }
};

// Check if array `a` contains `obj`.
Vex.Contains = function(a, obj) {
  var i = a.length;
  while (i--) {
    if (a[i] === obj) {
      return true;
    }
  }
  return false;
};

// Get the 2D Canvas context from DOM element `canvas_sel`.
Vex.getCanvasContext = function(canvas_sel) {
  if (!canvas_sel)
    throw new Vex.RERR("BadArgument", "Invalid canvas selector: " + canvas_sel);

  var canvas = document.getElementById(canvas_sel);
  if (!(canvas && canvas.getContext)) {
    throw new Vex.RERR("UnsupportedBrowserError",
        "This browser does not support HTML5 Canvas");
  }

  return canvas.getContext('2d');
};

// Draw a tiny dot marker on the specified canvas. A great debugging aid.
//
// `ctx`: Canvas context.
// `x`, `y`: Dot coordinates.
Vex.drawDot = function(ctx, x, y, color) {
  var c = color || "#f55";
  ctx.save();
  ctx.fillStyle = c;

  //draw a circle
  ctx.beginPath();
  ctx.arc(x, y, 3, 0, Math.PI*2, true);
  ctx.closePath();
  ctx.fill();
  ctx.restore();
};

// Benchmark. Run function `f` once and report time elapsed shifted by `s` milliseconds.
Vex.BM = function(s, f) {
  var start_time = new Date().getTime();
  f();
  var elapsed = new Date().getTime() - start_time;
  Vex.L(s + elapsed + "ms");
};

// Basic classical inheritance helper. Usage:
// ```
// // Vex.Inherit(Child, Parent, {
// //   getName: function() {return this.name;},
// //   setName: function(name) {this.name = name}
// // });
// //
// // Returns 'Child'.
// ```
Vex.Inherit = (function () {
  var F = function () {};
  // `C` is Child. `P` is parent. `O` is an object to
  // to extend `C` with.
  return function (C, P, O) {
    F.prototype = P.prototype;
    C.prototype = new F();
    C.superclass = P.prototype;
    C.prototype.constructor = C;
    Vex.Merge(C.prototype, O);
    return C;
  };
}());/**
 * Vex Flow - Mohit Muthanna <mohit@muthanna.com>
 */

/**
 * New namespace.
 */
Vex.Flow = {
  /**
   * The resolution used for all the rhythm timing in this
   * library.
   *
   * @const
   * @type {number}
   */
  RESOLUTION: 16384,

  /* Kerning (DEPRECATED) */
  IsKerned: true
};
// Fraction class that represents a rational number
// @author zz85
// @author incompleteopus (modifications)

Vex.Flow.Fraction = (function() {
  function Fraction(numerator, denominator) {
    this.set(numerator, denominator);
  }

  /**
   * GCD: Find greatest common divisor using Euclidean algorithm
   */
  Fraction.GCD = function(a, b) {
    if (typeof a !== "number" || typeof b !== "number") {
      throw new Vex.RERR("BadArgument", "Invalid numbers: " + a + ", " + b);
    }

    var t;

    while (b !== 0) {
      t = b;
      b = a % b;
      a = t;
    }

    return a;
  };

  /**
   * LCM: Lowest common multiple
   */
  Fraction.LCM = function(a, b) {
    return ((a * b) / Fraction.GCD(a, b));
  };

  /**
   * LCMM: Lowest common multiple for more than two numbers
   */
  Fraction.LCMM = function(args) {
    if (args.length === 0) {
      return 0;
    } else if (args.length == 1) {
      return args[0];
    } else if (args.length == 2) {
      return Vex.Flow.Fraction.LCM(args[0], args[1]);
    } else {
      var arg0 = args[0];
      args.shift();
      return Fraction.LCM(arg0, Vex.Flow.Fraction.LCMM(args));
    }
  };

  Fraction.prototype = {
    set: function(numerator, denominator) {
      this.numerator = numerator === undefined ? 1 : numerator;
      this.denominator = denominator === undefined ? 1 : denominator;
      return this;
    },

    value: function() {
      return this.numerator / this.denominator;
    },

    simplify: function() {
      var u = this.numerator;
      var d = this.denominator;

      var gcd = Vex.Flow.Fraction.GCD(u, d);
      u /= gcd;
      d /= gcd;

      if (d < 0) {
        d = -d;
        u = -u;
      }
      return this.set(u, d);
    },

    add: function(param1, param2) {
      var otherNumerator;
      var otherDenominator;

      if (param1 instanceof Vex.Flow.Fraction) {
        otherNumerator = param1.numerator;
        otherDenominator = param1.denominator;
      } else {
        if (param1 !== undefined) {
          otherNumerator = param1;
        } else {
          otherNumerator = 0;
        }

        if (param2 !== undefined) {
          otherDenominator = param2;
        } else {
          otherDenominator = 1;
        }
      }

      var lcm = Vex.Flow.Fraction.LCM(this.denominator, otherDenominator);
      var a = lcm / this.denominator;
      var b = lcm / otherDenominator;

      var u = this.numerator * a + otherNumerator * b;
      return this.set(u, lcm);
    },

    subtract: function(param1, param2) {
      var otherNumerator;
      var otherDenominator;

      if (param1 instanceof Vex.Flow.Fraction) {
        otherNumerator = param1.numerator;
        otherDenominator = param1.denominator;
      } else {
        if (param1 !== undefined) {
          otherNumerator = param1;
        } else {
          otherNumerator = 0;
        }

        if (param2 !== undefined) {
          otherDenominator = param2;
        } else {
          otherDenominator = 1;
        }
      }

      var lcm = Vex.Flow.Fraction.LCM(this.denominator, otherDenominator);
      var a = lcm / this.denominator;
      var b = lcm / otherDenominator;

      var u = this.numerator * a - otherNumerator * b;
      return this.set(u, lcm);
    },

    multiply: function(param1, param2) {
      var otherNumerator;
      var otherDenominator;

      if (param1 instanceof Vex.Flow.Fraction) {
        otherNumerator = param1.numerator;
        otherDenominator = param1.denominator;
      } else {
        if (param1 !== undefined) {
          otherNumerator = param1;
        } else {
          otherNumerator = 1;
        }

        if (param2 !== undefined) {
          otherDenominator = param2;
        } else {
          otherDenominator = 1;
        }
      }

      return this.set(this.numerator * otherNumerator, this.denominator * otherDenominator);
    },

    divide: function(param1, param2) {
      var otherNumerator;
      var otherDenominator;

      if (param1 instanceof Vex.Flow.Fraction) {
        otherNumerator = param1.numerator;
        otherDenominator = param1.denominator;
      } else {
        if (param1 !== undefined) {
          otherNumerator = param1;
        } else {
          otherNumerator = 1;
        }

        if (param2 !== undefined) {
          otherDenominator = param2;
        } else {
          otherDenominator = 1;
        }
      }

      return this.set(this.numerator * otherDenominator, this.denominator * otherNumerator);
    },


    // Simplifies both sides and checks if they are equal
    equals: function(compare) {
      var a = Vex.Flow.Fraction.__compareA.copy(compare).simplify();
      var b = Vex.Flow.Fraction.__compareB.copy(this).simplify();

      return (a.numerator === b.numerator) && (a.denominator === b.denominator);
    },

    // Creates a new copy with this current values
    clone: function() {
      return new Vex.Flow.Fraction(this.numerator, this.denominator);
    },

    // Copies value of another Fraction into itself
    copy: function(copy) {
      return this.set(copy.numerator, copy.denominator);
    },

    // Returns the integer component eg. (4/2) == 2
    quotient: function() {
      return Math.floor(this.numerator / this.denominator);
    },

    // Returns the fraction component when reduced to a mixed number
    fraction: function() {
      return this.numerator % this.denominator;
    },

    // Returns the absolute value
    abs: function() {
      this.denominator = Math.abs(this.denominator);
      this.numerator = Math.abs(this.numerator);
      return this;
    },

    // Returns a raw string representation
    toString: function() {
      return this.numerator + '/' + this.denominator;
    },

    // Returns a simplified string respresentation
    toSimplifiedString: function() {
      return Vex.Flow.Fraction.__tmp.copy(this).simplify().toString();
    },

    // Returns string representation in mixed form
    toMixedString: function() {
      var s = '';
      var q = this.quotient();
      var f = Vex.Flow.Fraction.__tmp.copy(this);

      if (q < 0) {
        f.abs().fraction();
      } else {
        f.fraction();
      }

      if (q !== 0) {
        s += q;

        if (f.numerator !== 0) {
          s += ' ' + f.toSimplifiedString();
        }
      } else {
        if (f.numerator === 0) {
          s = '0';
        } else {
          s = f.toSimplifiedString();
        }
      }

      return s;
    },

    // Parses a fraction string
    parse: function(str) {
      var i = str.split('/');
      var n = parseInt(i[0], 10);
      var d = (i[1]) ? parseInt(i[1], 10) : 1;

      return this.set(n, d);
    }
  };

  // Temporary cached objects
  Fraction.__compareA = new Fraction();
  Fraction.__compareB = new Fraction();
  Fraction.__tmp = new Fraction();

  return Fraction;
}());

// Vex Flow Notation
// Mohit Muthanna <mohit@muthanna.com>
//
// Copyright Mohit Muthanna 2010
//
// Requires vex.js.

Vex.Flow.STEM_WIDTH = 1.5;
Vex.Flow.STEM_HEIGHT = 32;
Vex.Flow.STAVE_LINE_THICKNESS = 2;

Vex.Flow.clefProperties = function(clef) {
  if (!clef) throw new Vex.RERR("BadArgument", "Invalid clef: " + clef);

  var props = Vex.Flow.clefProperties.values[clef];
  if (!props) throw new Vex.RERR("BadArgument", "Invalid clef: " + clef);

  return props;
};

Vex.Flow.clefProperties.values = {
  'treble':  { line_shift: 0 },
  'bass':    { line_shift: 6 },
  'tenor':   { line_shift: 4 },
  'alto':    { line_shift: 3 },
  'soprano': { line_shift: 1 },
  'percussion': { line_shift: 0 },
  'mezzo-soprano': { line_shift: 2 },
  'baritone-c': { line_shift: 5 },
  'baritone-f': { line_shift: 5 },
  'subbass': { line_shift: 7 },
  'french': { line_shift: -1 }
};

/*
  Take a note in the format "Key/Octave" (e.g., "C/5") and return properties.
*/
Vex.Flow.keyProperties = function(key, clef) {
  if (clef === undefined) {
    clef = 'treble';
  }

  var pieces = key.split("/");

  if (pieces.length < 2) {
    throw new Vex.RERR("BadArguments",
        "Key must have note + octave and an optional glyph: " + key);
  }

  var k = pieces[0].toUpperCase();
  var value = Vex.Flow.keyProperties.note_values[k];
  if (!value) throw new Vex.RERR("BadArguments", "Invalid key name: " + k);
  if (value.octave) pieces[1] = value.octave;

  var o = pieces[1];
  var base_index = (o * 7) - (4 * 7);
  var line = (base_index + value.index) / 2;
  line += Vex.Flow.clefProperties(clef).line_shift;

  var stroke = 0;

  if (line <= 0 && (((line * 2) % 2) === 0)) stroke = 1;  // stroke up
  if (line >= 6 && (((line * 2) % 2) === 0)) stroke = -1; // stroke down

  // Integer value for note arithmetic.
  var int_value = (typeof(value.int_val)!='undefined') ? (o * 12) +
    value.int_val : null;

  /* Check if the user specified a glyph. */
  var code = value.code;
  var shift_right = value.shift_right;
  if ((pieces.length > 2) && (pieces[2])) {
    var glyph_name = pieces[2].toUpperCase();
    var note_glyph = Vex.Flow.keyProperties.note_glyph[glyph_name];
    if (note_glyph) {
      code = note_glyph.code;
      shift_right = note_glyph.shift_right;
    }
  }

  return {
    key: k,
    octave: o,
    line: line,
    int_value: int_value,
    accidental: value.accidental,
    code: code,
    stroke: stroke,
    shift_right: shift_right,
    displaced: false
  };
};

Vex.Flow.keyProperties.note_values = {
  'C':  { index: 0, int_val: 0, accidental: null },
  'CN': { index: 0, int_val: 0, accidental: "n" },
  'C#': { index: 0, int_val: 1, accidental: "#" },
  'C##': { index: 0, int_val: 2, accidental: "##" },
  'CB': { index: 0, int_val: -1, accidental: "b" },
  'CBB': { index: 0, int_val: -2, accidental: "bb" },
  'D':  { index: 1, int_val: 2, accidental: null },
  'DN': { index: 1, int_val: 2, accidental: "n" },
  'D#': { index: 1, int_val: 3, accidental: "#" },
  'D##': { index: 1, int_val: 4, accidental: "##" },
  'DB': { index: 1, int_val: 1, accidental: "b" },
  'DBB': { index: 1, int_val: 0, accidental: "bb" },
  'E':  { index: 2, int_val: 4, accidental: null },
  'EN': { index: 2, int_val: 4, accidental: "n" },
  'E#': { index: 2, int_val: 5, accidental: "#" },
  'E##': { index: 2, int_val: 6, accidental: "##" },
  'EB': { index: 2, int_val: 3, accidental: "b" },
  'EBB': { index: 2, int_val: 2, accidental: "bb" },
  'F':  { index: 3, int_val: 5, accidental: null },
  'FN': { index: 3, int_val: 5, accidental: "n" },
  'F#': { index: 3, int_val: 6, accidental: "#" },
  'F##': { index: 3, int_val: 7, accidental: "##" },
  'FB': { index: 3, int_val: 4, accidental: "b" },
  'FBB': { index: 3, int_val: 3, accidental: "bb" },
  'G':  { index: 4, int_val: 7, accidental: null },
  'GN': { index: 4, int_val: 7, accidental: "n" },
  'G#': { index: 4, int_val: 8, accidental: "#" },
  'G##': { index: 4, int_val: 9, accidental: "##" },
  'GB': { index: 4, int_val: 6, accidental: "b" },
  'GBB': { index: 4, int_val: 5, accidental: "bb" },
  'A':  { index: 5, int_val: 9, accidental: null },
  'AN': { index: 5, int_val: 9, accidental: "n" },
  'A#': { index: 5, int_val: 10, accidental: "#" },
  'A##': { index: 5, int_val: 11, accidental: "##" },
  'AB': { index: 5, int_val: 8, accidental: "b" },
  'ABB': { index: 5, int_val: 7, accidental: "bb" },
  'B':  { index: 6, int_val: 11, accidental: null },
  'BN': { index: 6, int_val: 11, accidental: "n" },
  'B#': { index: 6, int_val: 12, accidental: "#" },
  'B##': { index: 6, int_val: 13, accidental: "##" },
  'BB': { index: 6, int_val: 10, accidental: "b" },
  'BBB': { index: 6, int_val: 9, accidental: "bb" },
  'R': { index: 6, int_val: 9, rest: true }, // Rest
  'X':  {
    index: 6,
    accidental: "",
    octave: 4,
    code: "v3e",
    shift_right: 5.5
  }
};

Vex.Flow.keyProperties.note_glyph = {
  /* Diamond */
  'D0':  { code: "v27", shift_right: -0.5 },
  'D1':  { code: "v2d", shift_right: -0.5 },
  'D2':  { code: "v22", shift_right: -0.5 },
  'D3':  { code: "v70", shift_right: -0.5 },

  /* Triangle */
  'T0':  { code: "v49", shift_right: -2 },
  'T1':  { code: "v93", shift_right: 0.5 },
  'T2':  { code: "v40", shift_right: 0.5 },
  'T3':  { code: "v7d", shift_right: 0.5 },

  /* Cross */
  'X0':  { code: "v92", shift_right: -2 },
  'X1':  { code: "v95", shift_right: -0.5 },
  'X2':  { code: "v7f", shift_right: 0.5 },
  'X3':  { code: "v3b", shift_right: -2 }
};

Vex.Flow.integerToNote = function(integer) {
  if (typeof(integer) == "undefined")
    throw new Vex.RERR("BadArguments", "Undefined integer for integerToNote");

  if (integer < -2)
    throw new Vex.RERR("BadArguments",
        "integerToNote requires integer > -2: " + integer);

  var noteValue = Vex.Flow.integerToNote.table[integer];
  if (!noteValue)
    throw new Vex.RERR("BadArguments", "Unknown note value for integer: " +
        integer);

  return noteValue;
};

Vex.Flow.integerToNote.table = {
  0: "C",
  1: "C#",
  2: "D",
  3: "D#",
  4: "E",
  5: "F",
  6: "F#",
  7: "G",
  8: "G#",
  9: "A",
  10: "A#",
  11: "B"
};


Vex.Flow.tabToGlyph = function(fret) {
  var glyph = null;
  var width = 0;
  var shift_y = 0;

  if (fret.toString().toUpperCase() == "X") {
    glyph = "v7f";
    width = 7;
    shift_y = -4.5;
  } else {
    width = Vex.Flow.textWidth(fret.toString());
  }

  return {
    text: fret,
    code: glyph,
    width: width,
    shift_y: shift_y
  };
};

Vex.Flow.textWidth = function(text) {
  return 6 * text.toString().length;
};

Vex.Flow.articulationCodes = function(artic) {
  return Vex.Flow.articulationCodes.articulations[artic];
};

Vex.Flow.articulationCodes.articulations = {
  "a.": {   // Staccato
    code: "v23",
    width: 4,
    shift_right: -2,
    shift_up: 8,
    shift_down: 0,
    between_lines: true
  },
  "av": {   // Staccatissimo
    code: "v28",
    width: 4,
    shift_right: 0,
    shift_up: 11,
    shift_down: 5,
    between_lines: true
  },
  "a>": {   // Accent
    code: "v42",
    width: 10,
    shift_right: 5,
    shift_up: 8,
    shift_down: 1,
    between_lines: true
  },
  "a-": {   // Tenuto
    code: "v25",
    width: 9,
    shift_right: -4,
    shift_up: 17,
    shift_down: 10,
    between_lines: true
  },
  "a^": {   // Marcato
    code: "va",
    width: 8,
    shift_right: 0,
    shift_up: -4,
    shift_down: -2,
    between_lines: false
  },
  "a+": {   // Left hand pizzicato
    code: "v8b",
    width: 9,
    shift_right: -4,
    shift_up: 12,
    shift_down: 12,
    between_lines: false
  },
  "ao": {   // Snap pizzicato
    code: "v94",
    width: 8,
    shift_right: 0,
    shift_up: -4,
    shift_down: 6,
    between_lines: false
  },
  "ah": {   // Natural harmonic or open note
    code: "vb9",
    width: 7,
    shift_right: 0,
    shift_up: -4,
    shift_down: 4,
    between_lines: false
  },
  "a@a": {   // Fermata above staff
    code: "v43",
    width: 25,
    shift_right: 0,
    shift_up: 8,
    shift_down: 10,
    between_lines: false
  },
  "a@u": {   // Fermata below staff
    code: "v5b",
    width: 25,
    shift_right: 0,
    shift_up: 0,
    shift_down: -4,
    between_lines: false
  },
  "a|": {   // Bow up - up stroke
    code: "v75",
    width: 8,
    shift_right: 0,
    shift_up: 8,
    shift_down: 10,
    between_lines: false
  },
  "am": {   // Bow down - down stroke
    code: "v97",
    width: 13,
    shift_right: 0,
    shift_up: 10,
    shift_down: 12,
    between_lines: false
  },
  "a,": {   // Choked
    code: "vb3",
    width: 6,
    shift_right: 8,
    shift_up: -4,
    shift_down: 4,
    between_lines: false
  }
};

Vex.Flow.accidentalCodes = function(acc) {
  return Vex.Flow.accidentalCodes.accidentals[acc];
};

Vex.Flow.accidentalCodes.accidentals = {
  "#": {
    code: "v18",
    width: 10,
    gracenote_width: 4.5,
    shift_right: 0,
    shift_down: 0
  },
  "##": {
    code: "v7f",
    width: 13,
    gracenote_width: 6,
    shift_right: -1,
    shift_down: 0
  },
  "b": {
    code: "v44",
    width: 8,
    gracenote_width: 4.5,
    shift_right: 0,
    shift_down: 0
  },
  "bb": {
    code: "v26",
    width: 14,
    gracenote_width: 8,
    shift_right: -3,
    shift_down: 0
  },
  "n": {
    code: "v4e",
    width: 8,
    gracenote_width: 4.5,
    shift_right: 0,
    shift_down: 0
  },
  "{": {   // Left paren for cautionary accidentals
    code: "v9c",
    width: 5,
    shift_right: 2,
    shift_down: 0
  },
  "}": {   // Right paren for cautionary accidentals
    code: "v84",
    width: 5,
    shift_right: 0,
    shift_down: 0
  },
  "db": {
    code: "v9e",
    width: 16,
    shift_right: 0,
    shift_down: 0
  },
  "d": {
    code: "vab",
    width: 10,
    shift_right: 0,
    shift_down: 0
  },
  "bbs": {
    code: "v90",
    width: 13,
    shift_right: 0,
    shift_down: 0
  },
  "++": {
    code: "v51",
    width: 13,
    shift_right: 0,
    shift_down: 0
  },
  "+": {
    code: "v78",
    width: 8,
    shift_right: 0,
    shift_down: 0
  }
};

Vex.Flow.keySignature = function(spec) {
  var keySpec = Vex.Flow.keySignature.keySpecs[spec];

  if (!keySpec) {
    throw new Vex.RERR("BadKeySignature",
        "Bad key signature spec: '" + spec + "'");
  }

  if (!keySpec.acc) {
    return [];
  }

  var code = Vex.Flow.accidentalCodes.accidentals[keySpec.acc].code;
  var notes = Vex.Flow.keySignature.accidentalList(keySpec.acc);

  var acc_list = [];
  for (var i = 0; i < keySpec.num; ++i) {
    var line = notes[i];
    acc_list.push({glyphCode: code, line: line});
  }

  return acc_list;
};

Vex.Flow.keySignature.keySpecs = {
  "C": {acc: null, num: 0},
  "Am": {acc: null, num: 0},
  "F": {acc: "b", num: 1},
  "Dm": {acc: "b", num: 1},
  "Bb": {acc: "b", num: 2},
  "Gm": {acc: "b", num: 2},
  "Eb": {acc: "b", num: 3},
  "Cm": {acc: "b", num: 3},
  "Ab": {acc: "b", num: 4},
  "Fm": {acc: "b", num: 4},
  "Db": {acc: "b", num: 5},
  "Bbm": {acc: "b", num: 5},
  "Gb": {acc: "b", num: 6},
  "Ebm": {acc: "b", num: 6},
  "Cb": {acc: "b", num: 7},
  "Abm": {acc: "b", num: 7},
  "G": {acc: "#", num: 1},
  "Em": {acc: "#", num: 1},
  "D": {acc: "#", num: 2},
  "Bm": {acc: "#", num: 2},
  "A": {acc: "#", num: 3},
  "F#m": {acc: "#", num: 3},
  "E": {acc: "#", num: 4},
  "C#m": {acc: "#", num: 4},
  "B": {acc: "#", num: 5},
  "G#m": {acc: "#", num: 5},
  "F#": {acc: "#", num: 6},
  "D#m": {acc: "#", num: 6},
  "C#": {acc: "#", num: 7},
  "A#m": {acc: "#", num: 7}
};

Vex.Flow.unicode = {
  // Unicode accidentals
  "sharp": String.fromCharCode(parseInt('266F', 16)),
  "flat" : String.fromCharCode(parseInt('266D', 16)),
  "natural": String.fromCharCode(parseInt('266E', 16)),
  // Major Chord
  "triangle": String.fromCharCode(parseInt('25B3', 16)),
  // half-diminished
  "o-with-slash": String.fromCharCode(parseInt('00F8', 16)),
   // Diminished
  "degrees": String.fromCharCode(parseInt('00B0', 16)),
  "circle": String.fromCharCode(parseInt('25CB', 16))
};

Vex.Flow.keySignature.accidentalList = function(acc) {
  if (acc == "b") {
    return [2, 0.5, 2.5, 1, 3, 1.5, 3.5];
  }
  else if (acc == "#") {
    return [0, 1.5, -0.5, 1, 2.5, 0.5, 2]; }
};

Vex.Flow.parseNoteDurationString = function(durationString) {
  if (typeof(durationString) !== "string") {
    return null;
  }

  var regexp = /(\d+|[a-z])(d*)([nrhms]|$)/;

  var result = regexp.exec(durationString);
  if (!result) {
    return null;
  }

  var duration = result[1];
  var dots = result[2].length;
  var type = result[3];

  if (type.length === 0) {
    type = "n";
  }

  return {
    duration: duration,
    dots: dots,
    type: type
  };
};

Vex.Flow.parseNoteData = function(noteData) {
  var duration = noteData.duration;

  // Preserve backwards-compatibility
  var durationStringData = Vex.Flow.parseNoteDurationString(duration);
  if (!durationStringData) {
    return null;
  }

  var ticks = Vex.Flow.durationToTicks(durationStringData.duration);
  if (ticks == null) {
    return null;
  }

  var type = noteData.type;

  if (type) {
    if (!(type === "n" || type === "r" || type === "h" ||
          type === "m" || type === "s")) {
      return null;
    }
  } else {
    type = durationStringData.type;
    if (!type) {
      type = "n";
    }
  }

  var dots = 0;
  if (noteData.dots) {
    dots = noteData.dots;
  } else {
    dots = durationStringData.dots;
  }

  if (typeof(dots) !== "number") {
    return null;
  }

  var currentTicks = ticks;

  for (var i = 0; i < dots; i++) {
    if (currentTicks <= 1) {
      return null;
    }

    currentTicks = currentTicks / 2;
    ticks += currentTicks;
  }

  return {
    duration: durationStringData.duration,
    type: type,
    dots: dots,
    ticks: ticks
  };
};

Vex.Flow.durationToTicks = function(duration) {
  var alias = Vex.Flow.durationAliases[duration];
  if (alias !== undefined) {
    duration = alias;
  }

  var ticks = Vex.Flow.durationToTicks.durations[duration];
  if (ticks === undefined) {
    return null;
  }

  return ticks;
};

Vex.Flow.durationToTicks.durations = {
  "1":    Vex.Flow.RESOLUTION / 1,
  "2":    Vex.Flow.RESOLUTION / 2,
  "4":    Vex.Flow.RESOLUTION / 4,
  "8":    Vex.Flow.RESOLUTION / 8,
  "16":   Vex.Flow.RESOLUTION / 16,
  "32":   Vex.Flow.RESOLUTION / 32,
  "64":   Vex.Flow.RESOLUTION / 64,
  "128":  Vex.Flow.RESOLUTION / 128,
  "256":  Vex.Flow.RESOLUTION / 256
};

Vex.Flow.durationAliases = {
  "w": "1",
  "h": "2",
  "q": "4",

  // This is the default duration used to render bars (BarNote). Bars no longer
  // consume ticks, so this should be a no-op.
  //
  // TODO(0xfe): This needs to be cleaned up.
  "b": "256"
};

Vex.Flow.durationToGlyph = function(duration, type) {
  var alias = Vex.Flow.durationAliases[duration];
  if (alias !== undefined) {
    duration = alias;
  }

  var code = Vex.Flow.durationToGlyph.duration_codes[duration];
  if (code === undefined) {
    return null;
  }

  if (!type) {
    type = "n";
  }

  var glyphTypeProperties = code.type[type];
  if (glyphTypeProperties === undefined) {
    return null;
  }

  return Vex.Merge(Vex.Merge({}, code.common), glyphTypeProperties);
};

Vex.Flow.durationToGlyph.duration_codes = {
  "1": {
    common: {
      head_width: 16,
      stem: false,
      stem_offset: 0,
      flag: false,
      stem_up_extension: -Vex.Flow.STEM_HEIGHT,
      stem_down_extension: -Vex.Flow.STEM_HEIGHT,
      gracenote_stem_up_extension: -Vex.Flow.STEM_HEIGHT,
      gracenote_stem_down_extension: -Vex.Flow.STEM_HEIGHT,
      tabnote_stem_up_extension: -Vex.Flow.STEM_HEIGHT,
      tabnote_stem_down_extension: -Vex.Flow.STEM_HEIGHT,
      dot_shiftY: 0,
      line_above: 0,
      line_below: 0
    },
    type: {
      "n": { // Whole note
        code_head: "v1d"
      },
      "h": { // Whole note harmonic
        code_head: "v46"
      },
      "m": { // Whole note muted
        code_head: "v92",
        stem_offset: -3
      },
      "r": { // Whole rest
        code_head: "v5c",
        head_width: 12,
        rest: true,
        position: "D/5",
        dot_shiftY: 0.5
      },
      "s": { // Whole note slash
        // Drawn with canvas primitives
        head_width: 15,
        position: "B/4"
      }
    }
  },
  "2": {
    common: {
      head_width: 10,
      stem: true,
      stem_offset: 0,
      flag: false,
      stem_up_extension: 0,
      stem_down_extension: 0,
      gracenote_stem_up_extension: -14,
      gracenote_stem_down_extension: -14,
      tabnote_stem_up_extension: 0,
      tabnote_stem_down_extension: 0,
      dot_shiftY: 0,
      line_above: 0,
      line_below: 0
    },
    type: {
      "n": { // Half note
        code_head: "v81"
      },
      "h": { // Half note harmonic
        code_head: "v2d"
      },
      "m": { // Half note muted
        code_head: "v95",
        stem_offset: -3
      },
      "r": { // Half rest
        code_head: "vc",
        head_width: 12,
        stem: false,
        rest: true,
        position: "B/4",
        dot_shiftY: -0.5
      },
      "s": { // Half note slash
        // Drawn with canvas primitives
        head_width: 15,
        position: "B/4"
      }
    }
  },
  "4": {
    common: {
      head_width: 10,
      stem: true,
      stem_offset: 0,
      flag: false,
      stem_up_extension: 0,
      stem_down_extension: 0,
      gracenote_stem_up_extension: -14,
      gracenote_stem_down_extension: -14,
      tabnote_stem_up_extension: 0,
      tabnote_stem_down_extension: 0,
      dot_shiftY: 0,
      line_above: 0,
      line_below: 0
    },
    type: {
      "n": { // Quarter note
        code_head: "vb"
      },
      "h": { // Quarter harmonic
        code_head: "v22"
      },
      "m": { // Quarter muted
        code_head: "v3e",
        stem_offset: -3
      },
      "r": { // Quarter rest
        code_head: "v7c",
        head_width: 8,
        stem: false,
        rest: true,
        position: "B/4",
        dot_shiftY: -0.5,
        line_above: 1.5,
        line_below: 1.5
      },
      "s": { // Quarter slash
         // Drawn with canvas primitives
         head_width: 15,
         position: "B/4"
      }
    }
  },
  "8": {
    common: {
      head_width: 10,
      stem: true,
      stem_offset: 0,
      flag: true,
      beam_count: 1,
      code_flag_upstem: "v54",
      code_flag_downstem: "v9a",
      stem_up_extension: 0,
      stem_down_extension: 0,
      gracenote_stem_up_extension: -14,
      gracenote_stem_down_extension: -14,
      tabnote_stem_up_extension: 0,
      tabnote_stem_down_extension: 0,
      dot_shiftY: 0,
      line_above: 0,
      line_below: 0
    },
    type: {
      "n": { // Eighth note
        code_head: "vb"
      },
      "h": { // Eighth note harmonic
        code_head: "v22"
      },
      "m": { // Eighth note muted
        code_head: "v3e"
      },
      "r": { // Eighth rest
        code_head: "va5",
        stem: false,
        flag: false,
        rest: true,
        position: "B/4",
        dot_shiftY: -0.5,
        line_above: 1.0,
        line_below: 1.0
      },
      "s": { // Eight slash
        // Drawn with canvas primitives
        head_width: 15,
        position: "B/4"
      }
    }
  },
  "16": {
    common: {
      beam_count: 2,
      head_width: 10,
      stem: true,
      stem_offset: 0,
      flag: true,
      code_flag_upstem: "v3f",
      code_flag_downstem: "v8f",
      stem_up_extension: 4,
      stem_down_extension: 0,
      gracenote_stem_up_extension: -14,
      gracenote_stem_down_extension: -14,
      tabnote_stem_up_extension: 0,
      tabnote_stem_down_extension: 0,
      dot_shiftY: 0,
      line_above: 0,
      line_below: 0
    },
    type: {
      "n": { // Sixteenth note
        code_head: "vb"
      },
      "h": { // Sixteenth note harmonic
        code_head: "v22"
      },
      "m": { // Sixteenth note muted
        code_head: "v3e"
      },
      "r": { // Sixteenth rest
        code_head: "v3c",
        head_width: 13,
        stem: false,
        flag: false,
        rest: true,
        position: "B/4",
        dot_shiftY: -0.5,
        line_above: 1.0,
        line_below: 2.0
      },
      "s": { // Sixteenth slash
        // Drawn with canvas primitives
        head_width: 15,
        position: "B/4"
      }
    }
  },
  "32": {
    common: {
      beam_count: 3,
      head_width: 10,
      stem: true,
      stem_offset: 0,
      flag: true,
      code_flag_upstem: "v47",
      code_flag_downstem: "v2a",
      stem_up_extension: 13,
      stem_down_extension: 9,
      gracenote_stem_up_extension: -12,
      gracenote_stem_down_extension: -12,
      tabnote_stem_up_extension: 9,
      tabnote_stem_down_extension: 5,
      dot_shiftY: 0,
      line_above: 0,
      line_below: 0
    },
    type: {
      "n": { // Thirty-second note
        code_head: "vb"
      },
      "h": { // Thirty-second harmonic
        code_head: "v22"
      },
      "m": { // Thirty-second muted
        code_head: "v3e"
      },
      "r": { // Thirty-second rest
        code_head: "v55",
        head_width: 16,
        stem: false,
        flag: false,
        rest: true,
        position: "B/4",
        dot_shiftY: -1.5,
        line_above: 2.0,
        line_below: 2.0
      },
      "s": { // Thirty-second slash
        // Drawn with canvas primitives
        head_width: 15,
        position: "B/4"
      }
    }
  },
  "64": {
    common: {
      beam_count: 4,
      head_width: 10,
      stem: true,
      stem_offset: 0,
      flag: true,
      code_flag_upstem: "va9",
      code_flag_downstem: "v58",
      stem_up_extension: 17,
      stem_down_extension: 13,
      gracenote_stem_up_extension: -10,
      gracenote_stem_down_extension: -10,
      tabnote_stem_up_extension: 13,
      tabnote_stem_down_extension: 9,
      dot_shiftY: 0,
      line_above: 0,
      line_below: 0
    },
    type: {
      "n": { // Sixty-fourth note
        code_head: "vb"
      },
      "h": { // Sixty-fourth harmonic
        code_head: "v22"
      },
      "m": { // Sixty-fourth muted
        code_head: "v3e"
      },
      "r": { // Sixty-fourth rest
        code_head: "v38",
        head_width: 18,
        stem: false,
        flag: false,
        rest: true,
        position: "B/4",
        dot_shiftY: -1.5,
        line_above: 2.0,
        line_below: 3.0
      },
      "s": { // Sixty-fourth slash
        // Drawn with canvas primitives
        head_width: 15,
        position: "B/4"
      }
    }
  },
  "128": {
      common: {
          beam_count: 5,
          head_width: 10,
          stem: true,
          stem_offset:0,
          flag: true,
          code_flag_upstem: "v9b",
          code_flag_downstem: "v30",
          stem_up_extension: 26,
          stem_down_extension: 22,
          gracenote_stem_up_extension: -8,
          gracenote_stem_down_extension: -8,
          tabnote_stem_up_extension: 22,
          tabnote_stem_down_extension: 18,
          dot_shiftY: 0,
          line_above: 0,
          line_below: 0
      },
      type: {
          "n": {  // Hundred-twenty-eight note
              code_head: "vb"
          },
          "h": { // Hundred-twenty-eight harmonic
              code_head: "v22"
          },
          "m": { // Hundred-twenty-eight muted
              code_head: "v3e"
          },
          "r": {  // Hundred-twenty-eight rest
              code_head: "vaa",
              head_width: 20,
              stem: false,
              flag: false,
              rest: true,
              position: "B/4",
              dot_shiftY: 1.5,
              line_above: 3.0,
              line_below: 3.0
          },
          "s": { // Hundred-twenty-eight rest
              // Drawn with canvas primitives
              head_width: 15,
              position: "B/4"
          }
      }
  }
};

// Some defaults
Vex.Flow.TIME4_4 = {
  num_beats: 4,
  beat_value: 4,
  resolution: Vex.Flow.RESOLUTION
};
Vex.Flow.Font = {"glyphs":{"v0":{"x_min":0,"x_max":514.5,"ha":525,"o":"m 236 648 b 246 648 238 648 242 648 b 288 646 261 648 283 648 b 472 513 364 634 428 587 b 514 347 502 464 514 413 b 462 163 514 272 499 217 b 257 44 409 83 333 44 b 50 163 181 44 103 83 b 0 347 14 217 0 272 b 40 513 0 413 12 464 b 236 648 87 591 155 638 m 277 614 b 253 616 273 616 261 616 b 242 616 247 616 243 616 b 170 499 193 609 181 589 b 159 348 163 446 159 398 b 166 222 159 308 161 266 b 201 91 174 138 183 106 b 257 76 215 81 235 76 b 311 91 277 76 299 81 b 347 222 330 106 338 138 b 353 348 352 266 353 308 b 344 499 353 398 351 446 b 277 614 333 587 322 606 m 257 -1 l 258 -1 l 255 -1 l 257 -1 m 257 673 l 258 673 l 255 673 l 257 673 "},"v1":{"x_min":-1.359375,"x_max":344.359375,"ha":351,"o":"m 126 637 l 129 638 l 198 638 l 266 638 l 269 635 b 274 631 272 634 273 632 l 277 627 l 277 395 b 279 156 277 230 277 161 b 329 88 281 123 295 106 b 344 69 341 81 344 79 b 337 55 344 62 343 59 l 333 54 l 197 54 l 61 54 l 58 55 b 50 69 53 59 50 62 b 65 88 50 79 53 81 b 80 97 72 91 74 93 b 117 156 103 113 112 129 b 117 345 117 161 117 222 l 117 528 l 100 503 l 38 406 b 14 383 24 384 23 383 b -1 398 5 383 -1 390 b 4 415 -1 403 1 409 b 16 437 5 416 10 426 l 72 539 l 100 596 b 121 632 119 631 119 631 b 126 637 122 634 125 635 m 171 -1 l 172 -1 l 170 -1 l 171 -1 m 171 673 l 172 673 l 170 673 l 171 673 "},"v2":{"x_min":-1.359375,"x_max":458.6875,"ha":468,"o":"m 197 648 b 216 648 201 648 208 648 b 258 646 232 648 253 648 b 419 546 333 637 393 599 b 432 489 428 528 432 509 b 356 342 432 440 405 384 b 235 278 322 313 288 295 b 69 170 166 256 107 217 b 69 169 69 170 69 169 b 69 169 69 169 69 169 b 74 173 69 169 72 170 b 209 222 112 204 163 222 b 310 195 247 222 274 215 b 371 179 332 184 352 179 b 396 181 379 179 387 179 b 428 202 409 184 423 194 b 442 212 431 209 436 212 b 458 197 450 212 458 206 b 441 148 458 190 449 165 b 299 44 409 84 353 44 b 288 45 295 44 292 44 b 250 61 274 45 268 49 b 122 99 212 86 164 99 b 73 91 104 99 88 97 b 28 63 53 84 34 72 b 14 54 25 56 20 54 b 1 62 9 54 4 56 l -1 65 l -1 79 b 0 99 -1 91 0 95 b 2 113 1 102 2 108 b 164 309 20 197 81 272 b 285 470 232 341 277 398 b 287 487 287 476 287 481 b 171 595 287 551 239 595 b 155 595 166 595 160 595 b 142 592 145 594 142 594 b 145 589 142 592 142 591 b 179 527 168 576 179 551 b 132 455 179 496 163 467 b 104 451 122 452 112 451 b 27 530 62 451 27 487 b 29 555 27 538 27 546 b 197 648 44 601 115 639 m 228 -1 l 230 -1 l 227 -1 l 228 -1 m 228 673 l 230 673 l 227 673 l 228 673 "},"v3":{"x_min":-1.359375,"x_max":409.6875,"ha":418,"o":"m 174 648 b 191 648 176 648 183 648 b 225 648 204 648 220 648 b 402 523 317 638 389 588 b 404 503 404 517 404 510 b 402 484 404 495 404 488 b 264 373 389 437 334 394 b 257 370 259 371 257 371 b 257 370 257 370 257 370 b 264 369 258 370 261 369 b 409 202 359 334 409 267 b 318 72 409 152 381 104 b 200 43 281 52 240 43 b 23 113 134 43 69 68 b 0 169 6 129 0 149 b 77 249 0 210 29 249 l 77 249 b 152 174 125 249 152 212 b 103 102 152 145 137 116 b 103 102 103 102 103 102 b 147 94 103 101 132 95 b 153 94 149 94 151 94 b 265 206 219 94 265 141 b 264 226 265 213 265 219 b 147 355 253 299 204 353 b 126 371 133 356 126 362 b 147 388 126 383 132 388 b 254 474 196 391 238 424 b 259 502 258 484 259 494 b 182 592 259 544 228 582 b 156 595 175 595 166 595 b 115 592 142 595 129 594 l 111 591 l 115 588 b 152 524 141 574 152 549 b 92 449 152 491 130 458 b 76 448 87 448 81 448 b -1 530 32 448 -1 488 b 20 581 -1 548 5 566 b 174 648 55 619 108 641 m 204 -1 l 205 -1 l 202 -1 l 204 -1 m 204 673 l 205 673 l 202 673 l 204 673 "},"v4":{"x_min":0,"x_max":468.21875,"ha":478,"o":"m 174 637 b 232 638 175 638 189 638 b 277 638 245 638 259 638 l 378 638 l 381 635 b 389 623 386 632 389 627 b 382 609 389 617 386 613 b 366 589 381 606 372 598 l 313 528 l 245 451 l 209 410 l 155 348 l 84 267 b 59 240 72 252 59 240 b 59 240 59 240 59 240 b 151 238 59 238 68 238 l 242 238 l 242 303 b 243 371 242 369 242 370 b 289 426 245 374 254 385 l 303 441 l 317 456 l 338 483 l 360 506 l 371 520 b 386 527 375 526 381 527 b 400 519 392 527 397 524 b 401 440 401 516 401 514 b 401 377 401 423 401 402 l 401 238 l 426 238 b 453 237 449 238 450 238 b 465 217 461 234 465 226 b 460 202 465 212 464 206 b 426 197 454 197 453 197 l 401 197 l 401 180 b 451 88 402 129 412 109 b 468 69 465 81 468 79 b 461 55 468 62 466 59 l 458 54 l 321 54 l 185 54 l 182 55 b 175 69 176 59 175 62 b 191 88 175 79 176 81 b 240 180 230 109 240 129 l 240 197 l 125 197 b 73 195 104 195 87 195 b 8 197 10 195 9 197 b 0 212 2 199 0 205 b 0 212 0 212 0 212 b 20 242 0 219 0 219 b 163 610 104 344 163 492 b 174 637 163 628 166 634 m 234 -1 l 235 -1 l 232 -1 l 234 -1 m 234 673 l 235 673 l 232 673 l 234 673 "},"v5":{"x_min":0,"x_max":409.6875,"ha":418,"o":"m 47 637 b 53 638 49 638 50 638 b 69 634 55 638 61 637 b 210 610 114 619 161 610 b 363 634 259 610 311 619 b 382 638 372 637 378 638 b 392 634 386 638 389 637 b 397 623 396 630 397 627 b 393 610 397 620 396 616 b 298 505 368 552 338 520 b 212 494 277 498 246 494 b 65 517 163 494 106 502 b 61 517 62 517 61 517 b 61 517 61 517 61 517 b 51 408 61 517 51 412 b 51 408 51 408 51 408 b 51 408 51 408 51 408 b 61 412 53 408 55 409 b 125 434 80 421 103 430 b 185 441 145 440 166 441 b 409 244 310 441 409 353 b 401 191 409 227 406 209 b 197 43 375 105 287 43 b 159 47 183 43 171 44 b 23 123 112 56 61 86 b 0 180 6 140 0 159 b 76 260 0 220 31 260 b 92 259 81 260 87 259 b 152 183 132 251 152 216 b 100 112 152 152 134 122 b 95 111 98 112 95 111 b 95 111 95 111 95 111 b 129 98 95 109 119 101 b 148 97 136 97 141 97 b 264 235 206 97 261 158 b 265 248 265 240 265 244 b 210 398 265 312 243 373 b 179 408 201 406 194 408 b 174 408 178 408 176 408 b 53 369 130 408 88 394 b 34 359 39 359 38 359 b 17 374 24 359 17 365 b 39 628 17 384 38 625 b 47 637 40 631 43 635 m 204 -1 l 205 -1 l 202 -1 l 204 -1 m 204 673 l 205 673 l 202 673 l 204 673 "},"v6":{"x_min":0,"x_max":475.03125,"ha":485,"o":"m 255 648 b 274 648 259 648 266 648 b 314 646 288 648 307 648 b 450 555 374 637 438 594 b 454 530 453 546 454 538 b 375 451 454 485 416 451 b 328 467 359 451 343 455 b 300 526 310 483 300 503 b 352 598 300 557 319 589 b 356 599 355 598 356 599 b 352 602 356 599 355 601 b 288 616 330 612 308 616 b 210 584 257 616 230 605 b 164 433 189 559 174 508 b 160 374 163 415 160 381 b 160 374 160 374 160 374 b 160 374 160 374 160 374 b 168 377 160 374 164 376 b 258 395 200 390 228 395 b 366 367 294 395 328 387 b 475 223 436 333 475 283 b 472 197 475 215 473 206 b 349 65 462 141 419 95 b 259 43 317 51 288 43 b 167 69 230 43 200 52 b 4 290 80 113 20 195 b 0 349 1 309 0 328 b 20 467 0 391 6 433 b 255 648 58 563 155 637 m 269 363 b 257 363 265 363 261 363 b 210 345 236 363 220 356 b 186 226 196 324 186 272 b 187 198 186 216 186 206 b 213 95 191 151 202 112 b 257 76 221 83 238 76 b 270 77 261 76 266 76 b 321 156 299 81 310 99 b 329 229 326 183 329 206 b 321 301 329 252 326 274 b 269 363 311 342 298 359 m 236 -1 l 238 -1 l 235 -1 l 236 -1 m 236 673 l 238 673 l 235 673 l 236 673 "},"v7":{"x_min":0,"x_max":442.359375,"ha":451,"o":"m 147 648 b 166 649 153 649 160 649 b 313 598 217 649 273 630 b 340 587 323 588 328 587 l 341 587 b 412 628 367 587 390 601 b 427 638 416 635 421 638 b 439 632 431 638 435 637 b 442 623 441 630 442 628 b 430 569 442 616 439 603 b 352 369 408 492 377 410 b 300 259 325 324 313 298 b 273 84 283 205 273 140 b 265 55 273 65 272 59 l 261 54 l 181 54 l 99 54 l 96 55 b 91 61 95 56 92 59 l 89 63 l 89 77 b 147 263 89 133 111 202 b 261 401 176 313 212 355 b 378 541 315 449 349 489 l 382 548 l 375 544 b 240 495 333 512 285 495 b 129 535 198 495 160 509 b 84 560 108 552 95 560 b 76 559 81 560 78 560 b 31 487 59 555 43 530 b 14 470 27 473 24 470 b 1 477 8 470 4 471 l 0 480 l 0 553 l 0 627 l 1 630 b 16 638 4 635 9 638 b 23 635 17 638 20 637 b 49 626 36 626 39 626 b 96 638 59 626 80 630 b 104 639 99 638 102 639 b 117 644 107 641 112 642 b 147 648 125 645 137 648 m 220 -1 l 221 -1 l 219 -1 l 220 -1 m 220 673 l 221 673 l 219 673 l 220 673 "},"v8":{"x_min":0,"x_max":488.640625,"ha":499,"o":"m 217 648 b 245 649 225 648 235 649 b 453 516 343 649 430 595 b 458 478 455 503 458 491 b 412 370 458 440 441 398 b 411 369 412 369 411 369 b 415 365 411 367 412 367 b 488 231 462 331 488 281 b 472 165 488 208 483 186 b 243 43 434 86 338 43 b 63 104 178 43 112 62 b 0 233 20 140 0 186 b 73 365 0 283 24 331 l 77 369 l 72 374 b 29 476 42 406 29 441 b 217 648 29 557 103 635 m 258 605 b 242 606 253 605 247 606 b 157 552 198 606 157 580 b 160 541 157 548 159 544 b 319 413 176 503 242 452 l 337 403 l 338 406 b 359 476 352 428 359 452 b 258 605 359 537 318 595 m 138 326 b 130 330 134 328 130 330 b 130 330 130 330 130 330 b 107 305 127 330 112 313 b 84 231 91 281 84 256 b 243 86 84 156 151 86 b 249 87 245 86 246 87 b 347 156 303 88 347 120 b 344 172 347 162 345 167 b 156 319 325 227 257 281 b 138 326 151 322 144 324 m 243 -1 l 245 -1 l 242 -1 l 243 -1 m 243 673 l 245 673 l 242 673 l 243 673 "},"v9":{"x_min":0,"x_max":475.03125,"ha":485,"o":"m 191 646 b 212 649 198 648 205 649 b 255 644 227 649 243 646 b 458 448 348 616 428 539 b 475 342 469 415 475 378 b 460 244 475 308 469 274 b 193 44 421 124 303 44 b 91 69 157 44 122 51 b 19 161 43 97 19 126 b 21 181 19 167 20 174 b 98 241 32 220 65 241 b 170 186 129 241 160 223 b 172 166 171 179 172 173 b 121 94 172 134 152 102 b 117 93 118 94 117 93 b 121 90 117 93 118 91 b 185 76 142 80 164 76 b 270 119 220 76 251 91 b 308 259 287 145 300 194 b 313 317 310 277 313 310 b 313 317 313 317 313 317 b 313 317 313 317 313 317 b 304 315 313 317 308 316 b 216 295 273 302 245 295 b 145 308 193 295 170 299 b 19 398 88 327 42 360 b 0 469 5 420 0 444 b 24 551 0 496 8 526 b 191 646 54 596 125 637 m 227 614 b 215 616 224 616 220 616 b 202 614 210 616 206 616 b 152 535 174 610 163 592 b 144 463 147 509 144 485 b 152 391 144 440 147 417 b 216 328 163 344 179 328 b 280 391 253 328 269 344 b 288 463 285 417 288 440 b 280 535 288 485 285 509 b 227 614 269 594 258 610 m 236 -1 l 238 -1 l 235 -1 l 236 -1 m 236 673 l 238 673 l 235 673 l 236 673 "},"va":{"x_min":-149.71875,"x_max":148.359375,"ha":151,"o":"m -8 -1 b -1 0 -5 -1 -4 0 b 16 -11 5 0 13 -4 b 83 -186 17 -12 47 -90 l 148 -358 l 148 -363 b 127 -385 148 -376 138 -385 b 112 -378 122 -385 118 -383 b 54 -226 110 -374 114 -385 b 0 -81 24 -147 0 -81 b -55 -226 -1 -81 -25 -147 b -114 -378 -115 -385 -111 -374 b -129 -385 -119 -383 -123 -385 b -149 -363 -140 -385 -149 -376 l -149 -358 l -84 -186 b -19 -11 -49 -90 -19 -12 b -8 -1 -17 -8 -12 -4 "},"vb":{"x_min":0,"x_max":428.75,"ha":438,"o":"m 262 186 b 273 186 266 186 272 186 b 274 186 273 186 274 186 b 285 186 274 186 280 186 b 428 48 375 181 428 122 b 386 -68 428 12 416 -29 b 155 -187 329 -145 236 -187 b 12 -111 92 -187 38 -162 b 0 -51 4 -91 0 -72 b 262 186 0 58 122 179 "},"vc":{"x_min":0,"x_max":447.8125,"ha":457,"o":"m 0 86 l 0 173 l 223 173 l 447 173 l 447 86 l 447 0 l 223 0 l 0 0 l 0 86 "},"vf":{"x_min":0,"x_max":370.21875,"ha":378,"o":"m 0 0 l 0 277 l 61 277 l 122 277 l 122 0 l 122 -278 l 61 -278 l 0 -278 l 0 0 m 246 -1 l 246 277 l 308 277 l 370 277 l 370 -1 l 370 -278 l 308 -278 l 246 -278 l 246 -1 "},"v10":{"x_min":0,"x_max":559.421875,"ha":571,"o":"m 5 127 b 14 127 6 127 9 127 b 51 126 25 127 43 127 b 175 98 93 122 138 112 l 186 94 b 279 51 210 86 255 65 b 285 47 280 51 283 48 b 319 27 291 44 311 31 l 326 22 b 359 0 332 19 352 4 l 367 -6 b 371 -9 368 -6 370 -8 l 379 -15 b 387 -22 383 -18 386 -20 l 398 -30 l 411 -40 l 417 -47 l 427 -55 l 434 -61 b 441 -66 436 -62 439 -65 l 446 -72 l 453 -77 l 462 -87 b 558 -188 490 -113 549 -176 b 559 -195 559 -191 559 -194 b 548 -205 559 -201 555 -205 b 541 -204 547 -205 544 -205 b 534 -198 539 -201 536 -199 l 525 -191 b 481 -162 518 -187 490 -167 b 472 -155 477 -159 472 -156 b 468 -152 470 -155 469 -154 b 461 -149 466 -152 464 -151 b 428 -130 454 -145 441 -137 b 371 -99 413 -122 372 -99 b 363 -95 371 -99 367 -98 b 353 -91 357 -94 353 -91 b 348 -90 353 -91 352 -91 b 332 -81 343 -87 341 -86 b 27 -12 230 -37 127 -13 b 0 -5 4 -11 2 -11 b 0 58 0 -2 0 27 b 0 122 0 88 0 120 b 5 127 1 124 4 126 "},"v11":{"x_min":-155.171875,"x_max":153.8125,"ha":157,"o":"m -137 353 b -130 353 -136 353 -133 353 b -112 349 -125 353 -119 352 b -100 342 -110 347 -104 344 b 0 317 -69 326 -35 317 b 111 349 38 317 76 328 b 129 353 117 352 123 353 b 153 327 142 353 153 344 b 144 302 153 320 153 317 b 27 6 93 226 50 113 b 21 -13 24 -11 24 -11 b 0 -26 17 -22 8 -26 b -24 -12 -9 -26 -19 -22 b -28 5 -24 -9 -27 -2 b -145 302 -53 117 -95 224 b -155 327 -155 317 -155 320 b -137 353 -155 340 -148 349 "},"v18":{"x_min":0,"x_max":323.9375,"ha":331,"o":"m 217 535 b 225 537 220 537 221 537 b 245 524 235 537 242 533 l 246 521 l 247 390 l 247 258 l 273 265 b 306 270 288 269 299 270 b 322 259 315 270 319 267 b 323 208 323 256 323 233 b 322 158 323 184 323 159 b 288 140 318 148 315 147 b 247 130 254 131 247 130 b 247 65 247 130 247 104 b 247 20 247 51 247 36 l 247 -88 l 273 -81 b 306 -76 289 -77 299 -76 b 318 -81 311 -76 315 -77 b 323 -123 323 -87 323 -86 l 323 -138 l 323 -154 b 318 -195 323 -191 323 -190 b 269 -210 314 -199 315 -199 b 249 -216 259 -213 250 -216 l 247 -216 l 247 -349 l 246 -483 l 245 -487 b 225 -499 242 -495 234 -499 b 206 -487 219 -499 210 -495 l 205 -483 l 205 -355 l 205 -227 l 204 -227 l 181 -233 l 138 -244 b 117 -249 127 -247 117 -249 b 115 -385 115 -249 115 -256 l 115 -523 l 114 -526 b 95 -538 110 -534 102 -538 b 74 -526 87 -538 78 -534 l 73 -523 l 73 -391 b 72 -260 73 -269 73 -260 b 72 -260 72 -260 72 -260 b 19 -273 61 -263 23 -273 b 0 -260 10 -273 4 -267 b 0 -209 0 -256 0 -256 l 0 -162 l 1 -158 b 61 -134 5 -148 5 -148 l 73 -131 l 73 -22 b 72 86 73 79 73 86 b 72 86 72 86 72 86 b 19 74 61 83 23 74 b 0 86 10 74 4 79 b 0 137 0 90 0 90 l 0 184 l 1 188 b 61 212 5 198 5 198 l 73 215 l 73 348 l 73 481 l 74 485 b 95 498 78 492 87 498 b 103 495 98 498 100 496 b 114 485 107 494 111 489 l 115 481 l 115 353 l 115 226 l 121 226 b 159 235 123 227 141 231 l 198 247 l 205 248 l 205 384 l 205 521 l 206 524 b 217 535 209 528 212 533 m 205 9 b 205 119 205 70 205 119 l 205 119 b 182 113 204 119 194 116 l 138 102 b 117 97 127 99 117 97 b 115 -12 115 97 115 91 l 115 -122 l 121 -120 b 159 -111 123 -119 141 -115 l 198 -101 l 205 -98 l 205 9 "},"v1b":{"x_min":0,"x_max":559.421875,"ha":571,"o":"m 544 204 b 548 204 545 204 547 204 b 559 194 555 204 559 199 b 559 190 559 192 559 191 b 530 156 559 188 556 184 b 462 86 510 134 481 104 b 453 76 458 81 454 77 l 446 70 l 441 65 b 434 59 439 63 436 61 l 427 54 b 409 37 426 51 416 44 b 392 23 398 29 394 26 b 387 19 389 22 387 20 b 379 13 386 19 383 16 l 371 8 l 367 5 l 359 -1 l 337 -16 b 285 -48 319 -29 298 -41 l 279 -52 b 186 -95 255 -66 210 -87 l 175 -99 b 23 -129 127 -117 68 -129 b 17 -129 20 -129 19 -129 b 1 -123 2 -129 2 -129 b 0 -49 0 -122 0 -83 b 0 4 0 -22 0 1 b 27 11 2 9 4 9 b 185 31 78 12 145 20 b 198 34 186 31 193 33 b 314 73 234 44 277 58 b 349 88 328 79 340 84 b 353 90 352 90 353 90 b 363 94 353 90 357 93 b 371 98 367 97 371 98 b 428 129 372 98 413 120 b 461 148 441 136 454 144 b 468 151 464 149 466 151 b 472 154 469 152 470 154 b 481 161 473 155 477 158 b 525 190 490 166 518 186 l 534 197 b 540 201 536 198 539 199 b 544 204 541 202 544 204 "},"v1d":{"x_min":0,"x_max":619.3125,"ha":632,"o":"m 274 184 b 307 186 285 186 296 186 b 616 22 465 186 597 116 b 619 -1 617 13 619 5 b 308 -187 619 -104 483 -187 b 0 -1 133 -187 0 -102 b 5 36 0 11 1 23 b 274 184 29 115 141 176 m 289 161 b 272 162 284 162 277 162 b 171 41 209 162 171 108 b 205 -73 171 5 182 -34 b 345 -163 243 -133 298 -163 b 436 -98 385 -163 420 -142 b 446 -43 443 -80 446 -62 b 289 161 446 47 377 147 "},"v1e":{"x_min":-402.890625,"x_max":401.53125,"ha":410,"o":"m -219 173 b -213 174 -217 174 -215 174 b -202 173 -209 174 -205 173 b -114 86 -200 172 -179 151 b -28 0 -66 37 -28 0 b 40 84 -28 0 2 37 b 117 174 111 173 110 172 b 122 174 118 174 119 174 b 132 173 125 174 129 173 b 295 11 134 172 171 134 l 307 -1 l 336 34 b 374 76 366 72 368 74 b 381 77 375 77 378 77 b 401 56 392 77 401 68 b 400 48 401 54 401 51 b 223 -172 397 41 230 -166 b 210 -176 220 -174 215 -176 b 201 -174 206 -176 204 -176 b 112 -87 198 -173 178 -152 b 27 0 65 -38 27 0 b -42 -86 27 0 -4 -38 b -118 -174 -112 -174 -111 -173 b -123 -176 -119 -176 -121 -176 b -133 -174 -126 -176 -130 -174 b -296 -12 -136 -173 -172 -137 l -308 0 l -337 -34 b -375 -77 -367 -73 -370 -76 b -382 -79 -377 -79 -379 -79 b -402 -58 -393 -79 -402 -69 b -401 -49 -402 -55 -402 -52 b -224 172 -398 -43 -228 167 b -219 173 -223 172 -220 173 "},"v1f":{"x_min":-340.28125,"x_max":338.921875,"ha":346,"o":"m -32 520 b -29 521 -31 520 -31 521 b -23 519 -27 521 -24 520 b -20 513 -21 517 -20 516 b -21 506 -20 512 -20 509 b -31 474 -23 502 -27 488 l -53 402 l -66 352 l -68 349 l -57 349 b -32 351 -51 349 -40 351 b 123 370 19 352 74 359 b 137 371 127 370 133 371 b 170 356 152 371 164 366 b 171 355 170 355 170 355 b 216 366 174 355 183 358 b 280 378 268 377 266 377 b 287 378 283 378 284 378 b 332 349 307 378 322 369 b 338 319 336 341 338 330 b 332 301 338 310 336 302 b 242 280 329 299 246 280 b 242 280 242 280 242 280 b 235 288 236 280 235 283 b 235 292 235 290 235 291 b 236 302 236 297 236 299 b 220 337 236 316 230 330 l 216 340 l 210 335 b 159 276 189 322 172 301 b 118 149 152 265 156 274 b 81 34 84 36 85 36 b -8 13 78 33 -4 13 b -8 13 -8 13 -8 13 b -14 20 -12 15 -14 15 b -8 44 -14 24 -12 31 b -2 66 -5 55 -2 65 b -2 66 -2 66 -2 66 l -2 66 b -43 41 -2 66 -21 55 b -114 4 -98 8 -98 8 b -144 0 -123 0 -134 0 b -242 99 -197 0 -242 43 b -242 109 -242 102 -242 105 b -212 219 -240 122 -242 116 b -185 312 -197 270 -185 312 l -185 312 b -189 312 -185 312 -186 312 b -259 312 -200 312 -227 312 b -321 310 -291 312 -310 310 b -334 312 -330 310 -334 312 b -340 319 -338 313 -340 316 b -336 326 -340 322 -338 324 b -291 337 -334 326 -314 331 l -247 347 l -210 348 b -172 348 -190 348 -172 348 b -168 363 -172 348 -171 355 b -145 442 -151 424 -145 441 b -133 452 -144 444 -140 446 l -77 489 b -32 520 -53 506 -32 520 m 57 334 b 53 335 55 335 54 335 b 44 334 50 335 49 335 b -70 316 8 326 -28 320 b -78 309 -78 316 -78 316 b -108 202 -80 305 -88 274 b -141 81 -136 112 -141 93 b -140 74 -141 79 -141 77 b -117 49 -137 59 -127 49 b -107 52 -114 49 -110 51 b 16 127 -106 54 14 126 b 42 217 16 127 42 215 b 49 241 42 222 44 229 b 73 320 53 251 73 317 b 57 334 73 327 65 333 "},"v22":{"x_min":0,"x_max":432.828125,"ha":442,"o":"m 209 186 b 213 187 210 187 212 187 b 216 187 215 187 216 187 b 224 174 216 186 220 180 b 420 -1 269 105 338 43 b 432 -12 431 -8 432 -9 b 421 -23 432 -15 432 -16 b 228 -180 345 -70 264 -137 b 219 -188 221 -188 221 -188 l 219 -188 b 208 -177 215 -188 215 -188 b 10 1 163 -106 93 -44 b 0 11 0 6 0 8 b 10 22 0 13 0 15 b 202 179 87 69 167 136 b 209 186 206 183 209 186 "},"v23":{"x_min":0,"x_max":133.390625,"ha":136,"o":"m 54 66 b 65 68 58 68 61 68 b 122 37 88 68 110 56 b 133 -1 130 26 133 12 b 104 -58 133 -23 123 -44 b 66 -69 92 -65 78 -69 b 10 -38 44 -69 23 -58 b 0 -1 2 -27 0 -13 b 54 66 0 30 20 61 "},"v25":{"x_min":0,"x_max":318.5,"ha":325,"o":"m 20 376 b 167 377 23 377 96 377 b 296 376 231 377 294 377 b 318 347 311 371 318 359 b 296 316 318 333 311 320 b 159 315 294 315 227 315 b 21 316 91 315 24 315 b 0 345 6 320 0 333 b 20 376 0 359 6 371 "},"v26":{"x_min":-21.78125,"x_max":483.1875,"ha":493,"o":"m -8 631 b -1 632 -6 632 -4 632 b 19 620 8 632 16 628 b 20 383 20 616 20 616 l 20 148 l 21 151 b 140 199 59 183 102 199 b 206 179 164 199 187 192 l 210 176 l 210 396 l 210 617 l 212 621 b 231 632 216 628 223 632 b 250 620 239 632 247 628 b 251 383 251 616 251 616 l 251 148 l 254 151 b 370 199 291 183 332 199 b 415 191 385 199 400 197 b 483 84 458 176 483 134 b 461 0 483 58 476 29 b 332 -142 439 -40 411 -72 l 255 -215 b 231 -229 240 -229 239 -229 b 216 -223 224 -229 220 -227 b 210 -158 210 -217 210 -223 b 210 -120 210 -148 210 -136 l 210 -29 l 205 -34 b 100 -142 182 -65 159 -88 l 23 -215 b -1 -229 9 -229 6 -229 b -20 -216 -9 -229 -17 -224 l -21 -212 l -21 201 l -21 616 l -20 620 b -8 631 -17 624 -13 630 m 110 131 b 96 133 106 133 100 133 b 89 133 93 133 91 133 b 24 87 63 129 40 113 l 20 80 l 20 -37 l 20 -156 l 23 -152 b 144 81 96 -72 144 20 l 144 83 b 110 131 144 113 134 126 m 341 131 b 328 133 337 133 332 133 b 322 133 326 133 323 133 b 257 87 296 129 273 113 l 251 80 l 251 -37 l 251 -156 l 255 -152 b 375 81 328 -72 375 20 l 375 83 b 341 131 375 113 367 126 "},"v27":{"x_min":0,"x_max":432.828125,"ha":442,"o":"m 208 184 b 213 187 209 186 212 187 b 224 176 217 187 221 183 b 245 147 225 172 235 159 b 419 -1 288 90 347 38 b 431 -8 424 -4 431 -8 b 432 -12 432 -9 432 -11 b 430 -18 432 -13 432 -16 b 364 -61 424 -20 383 -47 b 225 -183 307 -102 250 -152 b 223 -187 224 -184 223 -187 b 220 -188 221 -188 220 -188 b 208 -176 216 -188 210 -184 b 187 -148 205 -173 197 -159 b 12 0 144 -90 84 -38 b 0 11 4 5 0 8 b 16 24 0 13 4 18 b 183 158 83 69 141 115 b 208 184 194 169 198 173 m 183 105 b 176 113 181 109 176 113 b 172 109 176 113 175 112 b 92 45 149 90 117 62 l 88 41 l 102 31 b 247 -105 160 -6 210 -55 l 254 -115 l 257 -112 l 269 -102 b 340 -45 287 -87 319 -61 l 344 -43 l 330 -33 b 183 105 272 6 221 54 "},"v28":{"x_min":-73.5,"x_max":72.140625,"ha":74,"o":"m -72 252 l -73 254 l 0 254 l 72 254 l 70 252 b 0 -1 70 248 0 -1 b -72 252 -1 -1 -72 248 "},"v29":{"x_min":-590.71875,"x_max":589.359375,"ha":601,"o":"m 175 273 b 182 274 178 273 181 274 b 202 262 190 274 198 269 b 204 158 204 259 204 259 l 204 56 l 250 112 b 303 174 296 172 298 172 b 308 174 304 174 307 174 b 318 173 313 174 317 173 b 481 11 322 172 357 134 l 494 -1 l 522 34 b 560 76 553 72 555 74 b 567 77 563 77 564 77 b 589 56 579 77 589 68 b 586 48 589 54 588 51 b 411 -172 583 41 416 -166 b 397 -176 406 -174 401 -176 b 387 -174 393 -176 390 -176 b 299 -87 386 -173 366 -152 b 213 0 253 -38 213 0 b 208 -6 213 0 210 -2 l 204 -12 l 204 -147 b 204 -210 204 -173 204 -194 b 198 -292 204 -297 204 -287 b 183 -299 194 -297 189 -299 b 164 -287 175 -299 167 -295 b 163 -174 163 -284 163 -284 l 161 -63 l 119 -117 b 65 -176 76 -170 73 -176 b 61 -176 63 -176 62 -176 b -35 -87 51 -174 57 -180 b -121 0 -83 -38 -121 0 b -190 -86 -122 0 -152 -38 b -266 -174 -261 -174 -259 -173 b -272 -176 -268 -176 -270 -176 b -281 -174 -276 -176 -280 -174 b -371 -86 -284 -173 -304 -152 b -457 0 -417 -38 -457 0 l -457 0 b -477 -26 -457 0 -470 -16 b -548 -227 -524 -88 -548 -161 b -536 -303 -548 -254 -544 -280 b -533 -317 -534 -309 -533 -313 b -553 -338 -533 -330 -541 -338 b -577 -315 -566 -338 -571 -333 b -590 -227 -586 -287 -590 -258 b -518 -9 -590 -154 -564 -77 b -465 56 -509 2 -504 8 l -402 134 b -363 174 -374 170 -371 174 b -359 174 -362 174 -360 174 b -262 86 -351 174 -356 179 b -176 0 -216 37 -176 0 b -107 84 -176 0 -145 37 b -31 174 -36 173 -38 172 b -25 174 -29 174 -28 174 b -16 173 -23 174 -19 173 b 147 11 -13 172 35 123 l 157 -1 l 160 1 l 163 4 l 163 130 b 164 260 163 256 163 258 b 175 273 166 266 170 270 "},"v2a":{"x_min":-21.78125,"x_max":366.140625,"ha":374,"o":"m 276 1378 b 284 1379 279 1379 281 1379 b 306 1360 292 1379 298 1374 b 352 1247 326 1326 343 1286 b 366 1139 362 1213 366 1175 b 347 1009 366 1093 359 1049 l 344 1002 l 347 992 b 352 971 348 986 351 977 b 366 863 362 936 366 899 b 347 732 366 818 359 773 l 344 725 l 347 716 b 352 695 348 710 351 700 b 366 588 362 659 366 623 b 223 262 366 464 314 345 b 189 233 212 252 212 252 b 35 76 126 183 73 129 b -1 16 20 56 2 27 b -19 4 -4 9 -12 4 l -21 4 l -21 137 l -21 270 l -17 270 b 186 344 59 281 134 308 b 319 606 270 399 319 499 b 317 650 319 620 319 635 l 315 659 l 314 655 b 223 537 288 607 258 570 b 189 509 212 528 212 528 b 35 352 126 459 73 405 b -1 292 20 333 2 303 b -19 280 -4 285 -12 280 l -21 280 l -21 413 l -21 546 l -17 546 b 186 620 59 557 134 584 b 319 882 270 675 319 775 b 317 925 319 896 319 911 l 315 935 l 314 931 b 223 813 288 884 258 846 b 189 785 212 805 212 805 b 35 628 126 735 73 681 b -1 569 20 609 2 580 b -19 556 -4 562 -12 556 l -21 556 l -21 689 l -21 823 l -17 823 b 202 907 68 835 152 867 b 319 1157 280 968 319 1061 b 270 1338 319 1218 303 1281 b 262 1358 264 1349 262 1353 b 262 1364 262 1360 262 1363 b 276 1378 265 1371 269 1376 "},"v2d":{"x_min":0,"x_max":438.28125,"ha":447,"o":"m 212 190 b 219 191 213 191 216 191 b 236 176 225 191 228 190 b 419 18 277 105 341 49 b 436 5 431 13 434 11 b 438 -1 438 4 438 1 b 424 -16 438 -8 432 -13 b 356 -49 409 -20 379 -36 b 234 -180 306 -83 258 -133 b 219 -192 230 -188 224 -192 b 200 -176 213 -192 206 -187 b 9 -15 157 -102 89 -45 b 0 0 2 -12 0 -6 b 16 18 0 9 2 12 b 200 176 93 48 159 104 b 212 190 205 186 208 188 m 239 113 b 236 117 238 116 238 117 b 230 108 235 117 234 115 b 92 -15 196 58 140 8 b 88 -18 91 -16 88 -18 b 92 -20 88 -18 91 -19 b 198 -116 130 -43 166 -74 b 200 -117 200 -117 200 -117 b 201 -117 200 -117 201 -117 b 264 -43 212 -98 242 -62 b 345 15 288 -19 321 4 b 348 18 347 16 348 16 b 344 20 348 18 347 19 b 239 113 307 41 266 79 "},"v2f":{"x_min":-1.359375,"x_max":680.5625,"ha":694,"o":"m 597 1042 b 604 1042 600 1042 602 1042 b 642 1002 627 1042 642 1022 b 619 966 642 988 635 974 b 439 927 574 942 503 927 l 426 927 l 426 921 b 430 838 428 893 430 866 b 345 480 430 696 398 560 b 179 391 307 423 249 391 b 156 392 171 391 164 392 b 138 394 149 394 142 394 b 103 434 115 396 103 416 b 129 471 103 451 111 466 b 141 474 133 473 137 474 b 172 459 153 474 164 469 b 181 455 175 456 176 455 b 187 456 182 455 185 455 b 253 520 212 460 234 483 b 315 836 294 605 315 714 b 311 928 315 867 314 898 b 302 945 310 943 311 942 b 245 953 283 950 262 953 b 130 891 193 953 149 931 b 84 860 119 870 102 860 b 36 905 61 860 39 877 b 36 910 36 907 36 909 b 80 970 36 931 50 949 b 249 1017 125 1000 187 1017 b 322 1009 273 1017 299 1014 l 341 1003 b 436 991 372 995 406 991 b 577 1031 495 991 545 1004 b 597 1042 583 1038 590 1041 m 416 360 b 424 360 419 360 421 360 b 481 309 454 360 479 338 b 503 145 484 280 495 199 b 585 -185 525 16 555 -106 b 630 -245 596 -213 613 -237 l 634 -247 l 638 -245 b 647 -244 641 -245 645 -244 b 680 -278 666 -244 680 -262 b 664 -308 680 -290 675 -301 b 638 -312 658 -310 650 -312 b 613 -309 631 -312 623 -310 b 477 -201 555 -303 502 -260 b 417 -2 460 -159 434 -72 b 416 5 417 1 416 5 b 416 5 416 5 416 5 b 411 -5 415 5 413 0 b 359 -97 397 -33 377 -70 b 353 -106 355 -102 353 -105 b 359 -112 353 -108 355 -109 b 409 -130 375 -123 390 -129 b 426 -134 420 -130 421 -131 b 431 -147 428 -137 431 -141 b 420 -162 431 -152 427 -159 b 382 -169 409 -166 396 -169 b 323 -155 363 -169 341 -165 l 317 -152 l 314 -155 b 62 -303 240 -240 148 -295 b 36 -305 55 -305 44 -305 b 23 -303 29 -305 24 -305 b -1 -273 6 -299 -1 -287 b 31 -240 -1 -256 10 -240 b 36 -240 32 -240 34 -240 b 42 -241 38 -241 39 -241 b 134 -204 63 -241 99 -226 b 367 288 265 -115 357 81 b 375 330 368 313 370 320 b 416 360 383 347 400 358 m 360 -359 b 379 -359 363 -359 371 -359 b 424 -360 396 -359 416 -359 b 646 -502 536 -373 624 -430 b 649 -527 649 -510 649 -519 b 530 -673 649 -578 604 -635 l 521 -677 l 529 -681 b 653 -811 592 -714 637 -762 b 660 -853 658 -827 660 -839 b 645 -911 660 -873 656 -892 b 426 -1021 608 -981 519 -1021 b 283 -989 377 -1021 328 -1011 b 235 -949 249 -972 239 -964 b 234 -936 234 -946 234 -941 b 234 -928 234 -934 234 -931 l 235 -925 l 234 -927 l 225 -934 b 87 -982 186 -966 138 -982 b 80 -982 85 -982 83 -982 b 55 -981 70 -981 58 -981 b 17 -943 32 -981 17 -964 b 54 -904 17 -921 35 -904 b 78 -914 62 -904 72 -909 l 83 -918 l 88 -918 b 190 -831 122 -918 166 -881 b 269 -506 242 -727 269 -612 b 268 -462 269 -492 269 -477 b 266 -449 266 -458 266 -452 b 265 -444 266 -445 266 -444 b 257 -446 264 -444 261 -445 b 132 -545 196 -470 152 -505 b 88 -573 122 -563 104 -573 b 39 -523 63 -573 39 -553 b 63 -476 39 -505 44 -494 b 360 -359 136 -408 235 -369 m 419 -424 b 393 -423 411 -423 406 -423 l 375 -423 l 377 -426 b 379 -439 377 -427 378 -434 b 383 -510 382 -463 383 -487 b 314 -811 383 -609 360 -710 b 266 -893 296 -850 285 -870 b 264 -898 265 -896 264 -898 l 264 -898 b 264 -898 264 -898 264 -898 b 268 -898 264 -898 266 -898 b 273 -898 270 -898 272 -898 b 300 -909 283 -898 291 -900 b 426 -957 340 -941 385 -957 b 476 -949 443 -957 460 -954 b 547 -853 522 -931 547 -893 b 485 -745 547 -816 526 -775 b 397 -707 460 -727 432 -714 b 366 -675 375 -703 366 -692 b 396 -642 366 -657 377 -645 b 530 -557 455 -637 511 -601 b 536 -527 534 -548 536 -537 b 419 -424 536 -480 490 -437 "},"v30":{"x_min":-21.78125,"x_max":367.5,"ha":375,"o":"m 276 1900 b 284 1901 279 1900 281 1901 b 306 1883 291 1901 298 1896 b 367 1686 347 1825 367 1757 b 343 1558 367 1643 359 1600 l 338 1549 l 343 1537 b 367 1411 359 1497 367 1454 b 343 1282 367 1367 359 1324 l 338 1272 l 343 1261 b 367 1135 359 1221 367 1178 b 343 1007 367 1090 359 1047 l 338 996 l 343 985 b 367 859 359 945 367 902 b 343 731 367 814 359 771 l 338 720 l 343 709 b 367 582 359 667 367 626 b 289 362 367 503 340 426 b 239 312 276 345 259 330 b 29 77 152 237 76 152 b -1 18 14 54 2 30 b -19 4 -4 11 -12 4 l -21 4 l -21 133 l -20 260 l -13 262 b 98 299 17 269 62 284 b 111 305 103 302 110 305 b 167 334 123 310 156 327 b 319 595 264 391 319 491 b 313 659 319 616 318 638 b 310 667 311 664 311 667 b 307 663 310 667 308 666 b 240 588 289 637 269 614 b 16 331 141 505 62 413 b -1 294 8 316 1 302 b -19 280 -4 287 -12 280 l -21 280 l -21 408 l -20 537 l -13 538 b 98 576 17 545 62 560 b 111 581 103 578 110 581 b 167 610 123 587 156 603 b 319 871 264 667 319 767 b 313 935 319 892 318 913 b 310 942 311 941 311 942 b 307 939 310 942 308 941 b 240 864 289 913 269 889 b 16 607 141 781 62 689 b -1 570 8 592 1 578 b -19 556 -4 563 -12 556 l -21 556 l -21 684 l -20 813 l -13 814 b 98 852 17 821 62 836 b 111 857 103 855 110 857 b 167 886 123 863 156 880 b 319 1147 264 943 319 1043 b 313 1211 319 1168 318 1189 b 310 1218 311 1217 311 1218 b 307 1215 310 1218 308 1217 b 240 1140 289 1188 269 1165 b 16 884 141 1057 62 966 b -1 846 8 868 1 855 b -19 832 -4 839 -12 832 l -21 832 l -21 960 l -20 1089 l -13 1090 b 98 1128 17 1097 62 1111 b 111 1134 103 1131 110 1134 b 167 1163 123 1139 156 1156 b 319 1424 264 1220 319 1320 b 313 1486 319 1444 318 1465 b 310 1494 311 1493 311 1494 b 307 1492 310 1494 308 1493 b 240 1417 289 1464 269 1442 b 16 1160 141 1333 62 1242 b -1 1121 8 1145 1 1131 b -19 1109 -4 1115 -12 1109 l -21 1109 l -21 1236 l -20 1365 l -13 1367 b 98 1404 17 1374 62 1388 b 111 1410 103 1407 110 1410 b 250 1508 172 1437 215 1467 b 319 1701 296 1564 319 1633 b 270 1859 319 1757 303 1814 b 262 1882 265 1868 262 1875 b 276 1900 262 1890 266 1896 "},"v33":{"x_min":-423.3125,"x_max":421.9375,"ha":431,"o":"m -10 276 b -2 277 -8 277 -5 277 b 17 265 5 277 13 273 b 19 163 19 260 19 260 l 19 68 l 39 45 b 277 -95 122 -34 200 -81 b 289 -97 281 -97 285 -97 b 378 0 332 -97 371 -54 b 378 11 378 4 378 6 b 302 83 378 55 345 83 b 242 66 283 83 262 77 b 208 56 231 59 219 56 b 148 120 175 56 148 81 b 200 186 148 151 164 172 b 261 198 220 194 240 198 b 420 45 341 198 411 137 b 421 22 421 37 421 29 b 257 -198 421 -86 347 -188 b 242 -198 251 -198 247 -198 b 20 -105 181 -198 95 -163 l 19 -104 l 19 -183 b 19 -216 19 -195 19 -206 b 12 -273 19 -272 17 -267 b -2 -278 8 -277 2 -278 b -21 -266 -10 -278 -19 -274 b -23 -165 -23 -263 -23 -262 l -23 -69 l -44 -47 b -250 86 -117 23 -183 66 b -295 94 -270 93 -284 94 b -315 91 -302 94 -308 94 b -381 5 -356 81 -381 43 b -355 -56 -381 -16 -372 -40 b -299 -81 -338 -73 -319 -81 b -246 -68 -283 -81 -265 -77 b -212 -58 -234 -61 -223 -58 b -168 -77 -196 -58 -179 -65 b -151 -122 -156 -90 -151 -105 b -179 -174 -151 -141 -160 -162 b -239 -195 -194 -184 -217 -192 b -257 -197 -245 -195 -250 -197 b -423 -5 -349 -197 -423 -113 b -423 0 -423 -4 -423 -1 b -277 194 -420 97 -362 173 b -247 197 -268 197 -258 197 b -24 104 -185 197 -100 162 l -23 102 l -23 181 b -21 265 -23 260 -23 260 b -10 276 -20 269 -14 274 "},"v34":{"x_min":0,"x_max":622.03125,"ha":635,"o":"m 398 417 b 406 419 401 419 404 419 b 427 398 417 419 427 409 b 427 391 427 395 427 392 b 34 -274 424 385 38 -272 b 20 -280 29 -278 25 -280 b 0 -259 9 -280 0 -270 b 0 -252 0 -256 0 -254 b 393 413 2 -247 389 410 b 398 417 394 415 397 416 m 592 417 b 600 419 594 419 597 419 b 622 398 611 419 622 409 b 620 391 622 395 620 392 b 227 -274 617 385 231 -272 b 213 -280 223 -278 219 -280 b 193 -259 202 -280 193 -270 b 194 -252 193 -256 193 -254 b 586 413 196 -247 582 410 b 592 417 588 415 590 416 "},"v36":{"x_min":-1.359375,"x_max":1064.390625,"ha":1086,"o":"m 296 692 b 314 694 302 694 307 694 b 386 685 337 694 366 689 b 548 498 480 660 548 580 b 548 481 548 492 548 487 b 455 395 541 426 499 395 b 370 462 420 395 383 417 b 362 496 364 477 362 488 b 377 514 362 509 367 514 b 393 501 386 514 390 510 b 432 474 397 484 413 474 b 470 487 445 474 458 478 b 491 530 484 496 491 510 b 490 544 491 534 491 539 b 333 660 479 606 411 657 l 323 662 l 315 646 b 269 524 285 591 269 556 b 321 431 269 492 287 466 b 349 395 338 413 343 408 b 363 342 359 378 363 362 b 359 312 363 333 362 322 b 285 158 348 266 318 206 b 281 152 283 155 281 152 b 281 152 281 152 281 152 b 287 154 283 152 284 152 b 318 155 298 154 308 155 b 461 98 371 155 419 136 l 464 97 l 483 112 b 503 129 494 120 503 127 b 504 130 503 129 504 129 b 503 138 504 131 503 134 b 500 180 500 152 500 166 b 553 326 500 238 518 288 b 604 366 560 331 592 358 b 649 381 617 376 632 381 b 696 362 665 381 681 374 b 724 302 714 347 724 324 b 695 238 724 278 714 255 b 660 210 691 234 662 212 b 579 148 658 209 582 151 b 579 148 579 148 579 148 b 596 106 579 144 589 119 b 622 77 604 88 609 83 b 657 69 632 72 645 69 b 748 112 688 69 721 84 b 755 123 754 117 755 120 b 755 127 755 124 755 126 b 751 165 752 137 751 151 b 758 219 751 183 754 202 b 894 387 774 290 820 347 b 896 390 896 388 896 388 b 891 398 896 391 895 392 b 622 560 827 477 730 535 b 600 580 605 564 600 569 b 617 596 600 591 607 596 b 628 595 622 596 624 596 b 1057 248 846 552 1020 412 b 1064 191 1061 229 1064 209 b 922 0 1064 94 1005 9 b 902 -1 916 -1 909 -1 b 774 76 847 -1 800 26 b 769 83 770 81 770 83 b 769 81 769 83 769 83 b 627 -1 733 29 677 -1 b 548 27 597 -1 570 8 b 515 88 537 37 525 61 l 513 95 l 510 93 l 453 45 b 390 0 396 0 396 0 b 390 0 390 0 390 0 b 374 15 381 0 377 4 b 268 105 359 69 314 105 b 250 104 262 105 257 105 l 243 102 l 234 90 b 155 1 201 49 159 2 b 147 -1 152 0 149 -1 b 130 15 138 -1 130 6 b 132 20 130 18 132 19 b 136 31 133 22 134 27 b 220 131 149 74 178 109 b 231 137 225 134 230 136 b 302 278 280 202 302 244 b 265 335 302 299 295 309 b 209 442 234 363 213 402 b 209 455 209 446 209 451 b 279 648 209 502 232 564 l 285 659 l 283 659 b 176 627 238 653 210 645 b 57 477 111 594 66 538 b 55 459 55 471 55 464 b 72 409 55 437 61 415 b 93 403 78 405 87 403 b 152 467 123 403 151 431 b 168 488 153 483 157 488 b 185 462 181 488 185 483 l 185 460 b 137 344 183 409 168 369 b 78 322 119 328 98 322 b 13 360 50 322 25 335 b -1 426 4 380 -1 402 b 89 610 -1 488 32 559 b 296 692 147 659 210 685 m 926 348 b 921 353 924 351 922 353 b 914 348 920 353 918 351 b 823 167 857 306 823 237 b 828 124 823 154 826 138 b 890 31 837 79 862 40 b 896 31 892 31 894 31 b 956 104 916 31 940 59 b 970 191 965 129 970 159 b 966 241 970 208 969 224 b 926 348 959 277 945 313 m 627 326 b 619 326 624 326 622 326 b 598 316 611 326 604 323 b 568 215 579 288 568 255 b 568 208 568 213 568 210 b 571 183 570 195 570 184 l 571 183 b 594 201 571 183 582 191 l 634 231 b 660 259 653 247 656 248 b 664 278 662 266 664 272 b 627 326 664 299 649 320 "},"v38":{"x_min":-1.359375,"x_max":651.96875,"ha":665,"o":"m 389 644 b 405 645 394 645 400 645 b 504 566 450 645 492 613 b 507 541 506 557 507 549 b 480 471 507 514 498 489 l 477 467 l 483 470 b 609 591 539 485 586 531 b 613 601 611 595 613 599 b 631 609 619 607 624 609 b 651 588 641 609 651 602 b 200 -946 651 584 204 -941 b 182 -957 197 -953 190 -957 b 163 -945 174 -957 166 -953 b 161 -939 161 -942 161 -942 b 217 -743 161 -931 170 -904 b 272 -555 247 -639 272 -555 b 272 -555 272 -555 272 -555 b 264 -560 272 -555 268 -557 b 140 -603 227 -589 182 -603 b 36 -567 102 -603 65 -592 b -1 -487 12 -548 -1 -517 b 17 -427 -1 -466 5 -445 b 103 -380 38 -395 70 -380 b 191 -433 137 -380 172 -398 b 205 -484 201 -448 205 -466 b 178 -553 205 -509 196 -535 l 175 -557 l 182 -555 b 307 -435 236 -539 284 -494 b 372 -213 308 -430 372 -215 b 372 -213 372 -213 372 -213 b 364 -219 372 -213 368 -216 b 240 -262 328 -247 283 -262 b 137 -226 202 -262 166 -249 b 99 -145 112 -206 99 -176 b 118 -84 99 -124 106 -104 b 204 -38 138 -54 171 -38 b 292 -91 238 -38 273 -56 b 306 -141 302 -106 306 -124 b 279 -212 306 -167 296 -194 l 276 -215 l 281 -213 b 408 -93 336 -198 385 -151 b 473 129 409 -88 473 127 b 473 129 473 129 473 129 b 465 122 473 129 469 126 b 341 80 428 94 383 80 b 236 115 303 80 266 91 b 200 195 213 136 200 165 b 217 256 200 217 206 238 b 304 303 239 287 272 303 b 393 249 338 303 374 285 b 406 199 402 234 406 217 b 379 129 406 173 397 148 l 377 126 l 382 127 b 509 248 436 142 485 190 b 574 470 510 254 574 469 b 574 470 574 470 574 470 b 566 464 574 470 570 467 b 442 421 529 435 484 421 b 337 458 404 421 367 433 b 300 537 313 478 300 508 b 389 644 300 585 334 635 "},"v3b":{"x_min":0,"x_max":484.5625,"ha":494,"o":"m 228 245 b 239 247 234 247 239 247 b 243 247 240 247 242 247 b 303 238 257 247 287 242 b 484 -2 417 208 484 104 b 412 -177 484 -65 461 -127 b 243 -248 363 -226 303 -248 b 6 -63 138 -248 36 -180 b 0 -1 1 -41 0 -20 b 228 245 0 127 98 240 m 255 181 b 240 183 247 183 245 183 b 232 181 238 183 235 183 b 142 152 200 180 168 170 l 138 149 l 190 97 l 242 44 l 294 97 l 345 149 l 340 152 b 255 181 315 169 284 180 m 147 -54 l 197 -1 l 147 51 l 95 104 l 91 99 b 62 -1 72 70 62 34 b 66 -43 62 -15 63 -29 b 91 -101 72 -63 80 -84 l 95 -106 l 147 -54 m 393 99 b 389 104 390 102 389 104 b 337 51 389 104 366 80 l 285 -1 l 337 -54 l 389 -106 l 393 -101 b 421 -1 412 -72 421 -36 b 393 99 421 34 412 69 m 294 -98 b 242 -45 265 -69 242 -45 b 190 -98 242 -45 219 -69 l 138 -151 l 142 -154 b 242 -184 172 -174 206 -184 b 340 -154 276 -184 311 -174 l 345 -151 l 294 -98 "},"v3c":{"x_min":0,"x_max":450.53125,"ha":460,"o":"m 189 302 b 204 303 193 302 198 303 b 303 224 250 303 292 270 b 306 199 304 216 306 208 b 279 129 306 173 296 147 l 276 126 l 281 127 b 408 249 337 142 385 190 b 412 259 409 254 412 258 b 430 267 417 265 423 267 b 450 247 441 267 450 259 b 200 -605 450 242 204 -599 b 182 -616 197 -612 190 -616 b 163 -602 174 -616 166 -610 b 161 -598 161 -601 161 -601 b 217 -402 161 -589 170 -562 b 272 -213 247 -298 272 -213 b 272 -213 272 -213 272 -213 b 264 -219 272 -213 268 -216 b 140 -262 227 -247 182 -262 b 36 -226 102 -262 65 -249 b 0 -145 12 -206 0 -176 b 17 -84 0 -124 5 -104 b 103 -38 38 -54 70 -38 b 191 -91 137 -38 172 -56 b 205 -141 201 -106 205 -124 b 178 -212 205 -167 196 -194 l 175 -215 l 182 -213 b 307 -93 236 -198 284 -151 b 372 129 308 -88 372 127 b 372 129 372 129 372 129 b 364 122 372 129 368 126 b 240 80 328 94 283 80 b 137 115 202 80 166 91 b 99 194 111 136 99 165 b 189 302 99 244 133 292 "},"v3e":{"x_min":0,"x_max":406.96875,"ha":415,"o":"m 21 183 b 28 183 24 183 25 183 b 42 181 34 183 39 183 b 127 108 47 179 47 179 b 202 41 168 72 202 41 b 279 108 204 41 238 72 b 357 177 321 145 356 176 b 375 183 363 181 370 183 b 406 151 392 183 406 169 b 404 137 406 147 405 141 b 322 62 401 131 398 129 b 251 0 284 27 251 0 b 322 -63 251 -1 284 -29 b 404 -138 398 -130 401 -133 b 406 -152 405 -142 406 -148 b 375 -184 406 -170 392 -184 b 357 -179 370 -184 363 -183 b 279 -109 356 -177 321 -147 b 202 -43 238 -73 204 -43 b 127 -109 202 -43 168 -73 b 49 -179 85 -147 50 -177 b 31 -184 43 -183 36 -184 b 0 -152 13 -184 0 -170 b 2 -138 0 -148 0 -142 b 83 -63 5 -133 8 -130 b 155 0 122 -29 155 -1 b 83 62 155 0 122 27 b 8 129 43 97 10 127 b 0 151 2 136 0 144 b 21 183 0 165 8 177 "},"v3f":{"x_min":-24.5,"x_max":317.140625,"ha":324,"o":"m -24 -147 l -24 -5 l -20 -5 b -1 -19 -12 -5 -4 -11 b 58 -123 6 -43 31 -86 b 196 -278 93 -173 134 -219 b 317 -570 274 -356 317 -460 b 294 -713 317 -617 308 -666 l 289 -724 l 294 -735 b 317 -873 308 -780 317 -827 b 235 -1132 317 -963 288 -1054 b 209 -1165 228 -1140 224 -1146 b 189 -1177 204 -1172 196 -1177 b 171 -1164 182 -1177 175 -1172 b 168 -1154 170 -1161 168 -1159 b 181 -1132 168 -1149 172 -1142 b 269 -891 238 -1064 269 -975 b 269 -881 269 -886 269 -884 b 262 -814 269 -857 265 -827 b 258 -800 261 -811 259 -806 b 142 -628 240 -731 198 -667 b -8 -589 112 -606 47 -589 b -20 -589 -13 -589 -19 -589 l -24 -589 l -24 -449 l -24 -308 l -20 -308 b -1 -322 -12 -308 -4 -313 b 58 -424 6 -345 31 -388 b 194 -580 93 -476 136 -523 b 259 -660 221 -606 245 -635 b 261 -663 259 -662 261 -663 b 264 -656 262 -663 262 -660 b 269 -587 268 -632 269 -610 b 264 -521 269 -566 268 -544 b 262 -512 264 -517 262 -513 b 258 -498 261 -509 259 -503 b 142 -326 240 -428 198 -365 b -8 -287 112 -303 47 -288 b -20 -287 -13 -287 -19 -287 l -24 -287 l -24 -147 "},"v40":{"x_min":-1.359375,"x_max":436.921875,"ha":446,"o":"m 213 205 b 217 205 215 205 216 205 b 234 194 224 205 234 199 b 236 187 234 194 235 190 l 245 167 l 261 129 l 270 106 b 355 -61 294 54 329 -13 b 420 -163 381 -105 402 -138 b 436 -188 435 -184 436 -184 b 436 -191 436 -190 436 -190 b 421 -206 436 -201 431 -206 l 421 -206 l 416 -206 l 405 -201 b 217 -158 347 -172 283 -158 b 31 -201 153 -158 88 -172 l 20 -206 l 14 -206 l 14 -206 b 0 -191 5 -206 0 -201 b -1 -188 0 -190 -1 -190 b 14 -163 -1 -186 0 -184 b 95 -34 36 -136 72 -77 b 166 106 119 8 148 68 l 175 129 l 183 148 l 200 188 b 213 205 205 199 208 202 "},"v41":{"x_min":-1.359375,"x_max":556.6875,"ha":568,"o":"m 294 322 b 318 323 299 322 308 323 b 360 320 334 323 352 322 b 526 217 430 310 490 273 b 543 166 537 202 543 184 b 447 70 543 117 503 70 b 445 70 447 70 446 70 b 359 159 394 72 359 113 b 368 201 359 173 362 187 b 442 245 382 229 412 245 b 455 244 446 245 451 245 b 460 244 458 244 460 244 b 460 244 460 244 460 244 b 454 248 460 244 458 245 b 325 291 417 276 372 291 b 285 287 313 291 299 290 b 144 -2 183 269 144 190 b 281 -290 144 -208 179 -280 b 304 -291 289 -291 298 -291 b 524 -105 412 -291 506 -212 b 541 -84 526 -88 530 -84 b 556 -101 551 -84 556 -90 b 549 -138 556 -111 553 -122 b 334 -322 521 -237 435 -310 b 302 -324 323 -323 313 -324 b 13 -101 172 -324 54 -234 b -1 -1 4 -68 -1 -34 b 294 322 -1 161 121 303 "},"v42":{"x_min":-348.4375,"x_max":24.5,"ha":25,"o":"m -330 155 b -322 156 -329 156 -326 156 b -315 156 -319 156 -317 156 b -298 147 -311 155 -308 154 b -19 30 -224 98 -122 55 l 2 26 b 24 -1 17 22 24 13 b 2 -27 24 -15 17 -23 l -19 -31 b -298 -148 -122 -56 -224 -99 b -322 -158 -313 -158 -315 -158 b -348 -131 -338 -158 -348 -145 b -344 -117 -348 -127 -347 -122 b -328 -104 -341 -112 -338 -111 b -127 -8 -269 -65 -202 -33 b -106 0 -115 -4 -106 -1 b -127 6 -106 0 -115 2 b -328 102 -202 31 -269 63 b -344 116 -338 109 -341 111 b -348 130 -347 120 -348 124 b -330 155 -348 141 -341 152 "},"v43":{"x_min":-442.359375,"x_max":441,"ha":450,"o":"m -31 487 b -1 488 -21 488 -10 488 b 434 104 216 488 397 330 b 441 27 438 79 441 47 b 439 12 441 20 439 15 b 419 0 435 4 427 0 b 404 5 413 0 408 1 b 398 30 400 11 398 13 b 0 351 390 213 213 351 b -59 348 -20 351 -39 349 b -400 30 -251 324 -393 191 b -405 5 -400 13 -401 11 b -420 0 -409 1 -415 0 b -441 12 -428 0 -436 4 b -442 27 -441 15 -442 20 b -435 104 -442 47 -439 79 b -31 487 -401 316 -235 474 m -13 131 b -1 133 -9 133 -5 133 b 51 105 19 133 39 123 b 61 70 58 95 61 83 b 51 34 61 58 58 45 b -1 6 39 16 19 6 b -46 27 -17 6 -34 13 b -62 69 -57 38 -62 54 b -13 131 -62 98 -44 124 "},"v44":{"x_min":-21.78125,"x_max":251.8125,"ha":257,"o":"m -8 631 b -1 632 -6 632 -4 632 b 19 620 8 632 16 628 b 20 383 20 616 20 616 l 20 148 l 21 151 b 137 199 59 183 99 199 b 182 191 152 199 167 197 b 251 84 227 176 251 134 b 228 0 251 58 243 29 b 100 -142 206 -40 178 -72 l 23 -215 b 0 -229 9 -229 6 -229 b -20 -216 -9 -229 -17 -224 l -21 -212 l -21 201 l -21 616 l -20 620 b -8 631 -17 624 -13 630 m 110 131 b 96 133 106 133 100 133 b 89 133 93 133 91 133 b 24 87 63 129 40 113 l 20 80 l 20 -37 l 20 -156 l 23 -152 b 144 81 96 -72 144 20 l 144 83 b 110 131 144 113 134 126 "},"v45":{"x_min":-402.890625,"x_max":401.53125,"ha":410,"o":"m -10 273 b -4 274 -9 273 -6 274 b 16 262 4 274 12 269 b 17 158 17 259 17 259 l 17 56 l 62 112 b 117 174 110 172 110 172 b 122 174 118 174 119 174 b 132 173 125 174 129 173 b 295 11 134 172 171 134 l 307 -1 l 336 34 b 374 76 366 72 368 74 b 381 77 375 77 378 77 b 401 56 392 77 401 68 b 400 48 401 54 401 51 b 223 -172 397 41 230 -166 b 210 -176 220 -174 215 -176 b 201 -174 206 -176 204 -176 b 112 -87 198 -173 178 -152 b 27 0 65 -38 27 0 b 21 -6 27 0 24 -2 l 17 -12 l 17 -147 b 17 -210 17 -173 17 -194 b 10 -292 17 -297 16 -287 b -2 -299 6 -297 2 -299 b -21 -287 -10 -299 -19 -295 b -24 -174 -23 -284 -23 -284 l -24 -63 l -66 -117 b -121 -176 -110 -170 -114 -176 b -125 -176 -122 -176 -123 -176 b -296 -12 -134 -174 -125 -184 l -308 0 l -337 -34 b -375 -77 -367 -73 -370 -76 b -382 -79 -377 -79 -379 -79 b -402 -58 -393 -79 -402 -69 b -401 -49 -402 -55 -402 -52 b -224 170 -398 -43 -231 165 b -212 174 -221 173 -216 174 b -202 173 -208 174 -205 174 b -39 11 -200 172 -151 122 l -28 -1 l -25 1 l -24 4 l -24 130 b -23 260 -24 256 -24 258 b -10 273 -20 266 -16 270 "},"v46":{"x_min":0,"x_max":627.46875,"ha":640,"o":"m 306 190 b 314 191 308 191 311 191 b 326 184 318 191 322 190 l 336 173 b 510 52 377 127 442 80 b 515 49 513 51 515 49 b 611 16 537 40 579 24 b 627 0 624 13 627 9 b 607 -18 627 -11 624 -13 b 330 -181 490 -49 389 -109 b 314 -192 323 -190 319 -192 b 306 -191 311 -192 308 -192 b 294 -177 302 -188 302 -188 b 257 -140 287 -170 265 -148 b 19 -18 193 -84 114 -44 b 0 0 2 -13 0 -11 b 16 16 0 9 2 13 b 110 49 47 24 89 40 b 117 52 111 49 114 51 b 145 65 126 56 130 58 b 281 163 200 93 245 124 b 300 186 288 170 291 174 b 306 190 300 187 303 188 m 317 137 b 313 142 315 141 314 142 b 308 137 313 142 311 141 b 161 4 276 84 220 33 b 155 0 159 1 155 0 b 163 -4 155 0 159 -2 b 308 -138 220 -34 276 -84 b 313 -142 311 -141 313 -142 b 317 -138 314 -142 315 -141 b 464 -4 351 -84 406 -34 b 470 0 468 -2 470 0 b 464 4 470 0 468 1 b 317 137 406 33 351 84 "},"v47":{"x_min":-24.5,"x_max":315.78125,"ha":322,"o":"m -24 -145 l -24 -5 l -20 -5 b 1 -26 -10 -5 -6 -9 b 175 -241 31 -86 96 -166 b 314 -548 259 -323 304 -420 b 315 -589 315 -555 315 -571 b 314 -630 315 -606 315 -623 b 298 -730 311 -664 306 -699 l 295 -742 l 296 -748 b 314 -850 304 -778 311 -813 b 315 -892 315 -857 315 -874 b 314 -932 315 -909 315 -925 b 298 -1032 311 -967 306 -1002 l 295 -1045 l 296 -1050 b 314 -1153 304 -1081 311 -1115 b 315 -1193 315 -1160 315 -1177 b 314 -1235 315 -1211 315 -1228 b 217 -1526 306 -1338 270 -1444 b 201 -1533 213 -1532 208 -1533 b 182 -1522 193 -1533 185 -1529 b 179 -1514 181 -1518 179 -1517 b 189 -1489 179 -1508 182 -1501 b 266 -1217 240 -1403 266 -1308 b 262 -1156 266 -1196 265 -1177 b 110 -907 247 -1043 190 -950 b 0 -889 87 -895 50 -889 l -1 -889 l -24 -889 l -24 -749 l -24 -610 l -20 -610 b 1 -631 -10 -610 -6 -614 b 175 -846 31 -691 96 -771 b 259 -956 213 -884 236 -914 b 265 -966 262 -961 264 -966 b 265 -966 265 -966 265 -966 b 265 -953 265 -964 265 -959 b 266 -920 266 -943 266 -932 b 262 -853 266 -898 265 -873 b 110 -605 247 -741 190 -648 b 0 -587 87 -592 50 -587 l -1 -587 l -24 -587 l -24 -448 l -24 -308 l -20 -308 b 1 -328 -10 -308 -6 -312 b 175 -544 31 -388 96 -469 b 259 -655 213 -581 236 -612 b 265 -663 262 -659 264 -663 b 265 -663 265 -663 265 -663 b 265 -650 265 -663 265 -657 b 266 -617 266 -641 266 -630 b 262 -551 266 -595 265 -570 b 110 -303 247 -438 190 -345 b 0 -284 87 -290 50 -284 l -1 -284 l -24 -284 l -24 -145 "},"v49":{"x_min":0,"x_max":630.203125,"ha":643,"o":"m 308 204 b 314 205 310 205 313 205 b 326 201 319 205 323 204 b 355 154 328 199 338 180 b 401 83 362 142 392 95 l 409 72 b 431 41 412 66 424 49 b 619 -174 498 -51 570 -134 b 630 -192 626 -180 630 -186 b 626 -202 630 -195 628 -199 b 616 -206 623 -205 620 -206 b 552 -188 608 -206 592 -202 b 310 -155 488 -169 392 -155 b 268 -156 295 -155 281 -155 b 77 -188 197 -161 126 -173 b 13 -206 35 -202 20 -206 b 9 -206 12 -206 10 -206 b 0 -191 2 -202 0 -197 b 8 -176 0 -186 2 -180 b 204 49 58 -136 138 -43 l 220 72 l 227 83 b 295 188 245 108 281 166 b 308 204 299 197 304 202 m 315 147 b 314 147 315 147 314 147 b 314 147 314 147 314 147 b 306 129 314 145 310 138 l 296 105 b 281 72 292 97 284 77 l 274 56 b 181 -123 247 -4 212 -72 l 174 -134 l 176 -133 b 314 -123 215 -127 272 -123 b 451 -133 356 -123 413 -127 l 454 -134 l 449 -123 b 353 56 417 -72 381 -4 l 347 72 b 332 105 344 77 336 97 l 322 129 b 315 147 318 138 315 145 "},"v4a":{"x_min":70.78125,"x_max":378.390625,"ha":315,"o":"m 246 373 b 254 373 249 373 251 373 b 372 324 303 373 360 351 b 378 302 377 317 378 309 b 338 251 378 278 362 255 b 328 249 334 249 332 249 b 283 294 303 249 283 270 b 288 315 283 301 284 308 b 289 319 289 317 289 319 b 289 319 289 319 289 319 b 283 320 289 320 287 320 b 270 322 279 322 274 322 b 206 288 242 322 215 308 b 206 283 206 287 206 285 b 257 223 206 267 230 238 b 284 206 272 213 277 210 b 351 90 328 173 351 130 b 340 47 351 74 348 59 b 205 -30 314 -2 264 -30 b 182 -29 198 -30 190 -30 b 84 15 147 -24 103 -5 b 70 48 74 24 70 36 b 108 99 70 70 85 94 b 121 102 112 101 117 102 b 167 56 147 102 167 80 b 159 31 167 48 164 40 l 156 26 l 157 26 b 190 20 167 22 178 20 b 220 26 201 20 212 22 b 258 65 243 34 258 51 b 257 70 258 66 258 69 b 204 126 249 94 234 109 b 114 258 148 158 114 209 b 125 302 114 273 118 288 b 246 373 147 342 193 370 "},"v4b":{"x_min":0,"x_max":503.609375,"ha":514,"o":"m 274 430 b 277 430 276 430 277 430 b 310 394 296 430 310 415 b 308 383 310 391 308 387 b 306 367 307 381 307 374 b 236 120 298 305 272 210 b 40 -273 189 -5 125 -134 b 20 -287 35 -283 27 -287 b 5 -281 14 -287 9 -285 b 0 -267 1 -277 0 -273 b 9 -242 0 -262 2 -255 b 246 395 137 -12 232 242 b 274 430 249 416 257 427 m 468 430 b 472 430 469 430 470 430 b 503 394 490 430 503 415 b 502 383 503 391 503 387 b 499 367 502 381 500 374 b 431 120 491 305 465 210 b 234 -273 382 -5 318 -134 b 213 -287 228 -283 220 -287 b 198 -281 208 -287 202 -285 b 193 -267 194 -277 193 -273 b 202 -242 193 -262 196 -255 b 439 395 330 -12 426 242 b 468 430 442 416 451 427 "},"v4d":{"x_min":-311.6875,"x_max":310.328125,"ha":317,"o":"m -9 388 b -2 390 -8 390 -5 390 b 5 388 1 390 4 390 b 19 378 10 387 16 383 b 23 333 23 371 23 371 b 24 298 23 299 24 298 b 81 276 34 298 65 285 b 213 91 145 240 190 177 b 224 24 217 76 224 36 b 257 24 224 24 235 24 b 299 19 292 24 292 24 b 310 -1 306 15 310 6 b 299 -23 310 -11 306 -19 b 257 -27 292 -27 292 -27 b 224 -29 235 -27 224 -29 b 213 -95 224 -40 217 -80 b 81 -280 190 -181 145 -244 b 24 -301 65 -290 34 -301 b 23 -335 24 -301 23 -303 l 23 -340 b 17 -381 23 -374 23 -374 b -1 -391 13 -388 5 -391 b -21 -381 -9 -391 -17 -388 b -27 -340 -27 -374 -27 -374 l -27 -335 b -28 -301 -27 -303 -27 -301 b -85 -280 -38 -301 -69 -290 b -217 -95 -149 -244 -194 -181 b -228 -29 -221 -80 -228 -40 b -259 -27 -228 -29 -238 -27 b -300 -23 -294 -27 -294 -27 b -311 -2 -307 -19 -311 -11 b -294 23 -311 8 -304 19 b -259 24 -291 23 -284 24 b -228 24 -239 24 -228 24 b -217 91 -228 36 -221 76 b -85 276 -194 177 -149 240 b -28 298 -69 285 -38 298 b -27 333 -27 298 -27 299 b -27 371 -27 362 -27 369 b -9 388 -24 378 -17 385 m -27 136 b -28 247 -27 197 -28 247 b -61 216 -31 247 -53 226 b -123 33 -95 172 -121 98 l -125 24 l -76 24 l -27 24 l -27 136 m 29 242 b 24 247 27 245 24 247 b 23 136 24 247 23 197 l 23 24 l 72 24 l 121 24 l 119 33 b 29 242 115 116 77 206 m -27 -140 l -27 -27 l -76 -27 l -125 -27 l -123 -36 b -61 -220 -121 -102 -95 -176 b -28 -251 -53 -230 -31 -251 b -27 -140 -28 -251 -27 -201 m 119 -36 l 121 -27 l 72 -27 l 23 -27 l 23 -140 b 24 -251 23 -201 24 -251 b 57 -220 27 -251 49 -230 b 119 -36 91 -176 117 -102 "},"v4e":{"x_min":0,"x_max":239.5625,"ha":244,"o":"m 10 460 b 20 462 13 462 14 462 b 39 449 28 462 35 458 l 40 446 l 40 326 b 40 205 40 259 40 205 b 127 227 40 205 80 215 b 220 249 196 244 213 249 b 227 247 224 249 225 248 b 238 237 231 245 235 241 l 239 233 l 239 -106 l 239 -448 l 238 -451 b 219 -463 234 -459 225 -463 b 198 -451 210 -463 202 -459 l 197 -448 l 197 -324 b 197 -201 197 -248 197 -201 b 110 -223 196 -201 157 -210 b 17 -245 42 -240 24 -245 b 10 -242 13 -245 13 -244 b 0 -233 6 -241 2 -237 l 0 -230 l 0 108 l 0 446 l 0 449 b 10 460 2 453 6 458 m 197 22 b 197 70 197 41 197 58 b 196 116 197 113 197 116 l 196 116 b 118 97 196 116 160 106 l 40 77 l 40 -18 b 40 -112 40 -69 40 -112 l 119 -93 l 197 -73 l 197 22 "},"v51":{"x_min":-1.359375,"x_max":455.96875,"ha":465,"o":"m 352 541 b 357 542 353 542 355 542 b 377 530 364 542 372 537 l 378 526 l 378 394 l 379 262 l 404 266 b 436 270 420 269 430 270 b 450 265 443 270 446 269 b 455 220 455 259 455 260 l 455 208 l 455 161 l 454 156 b 411 140 449 147 447 147 b 378 133 393 137 379 134 b 378 68 378 133 378 106 b 378 22 378 54 378 38 l 379 -87 l 404 -83 b 436 -79 420 -80 430 -79 b 450 -84 443 -79 446 -80 b 455 -129 455 -90 455 -88 l 455 -141 l 455 -188 l 454 -192 b 413 -209 449 -202 447 -202 b 382 -215 398 -212 383 -215 l 378 -215 l 378 -345 l 378 -380 b 375 -485 378 -484 378 -480 b 357 -494 371 -491 364 -494 b 340 -485 351 -494 344 -491 b 336 -383 337 -480 336 -484 l 336 -349 l 336 -223 l 334 -223 b 291 -231 334 -223 314 -227 l 247 -240 l 247 -371 l 246 -503 l 245 -506 b 225 -519 242 -514 234 -519 b 206 -506 219 -519 210 -514 l 205 -503 l 205 -376 l 205 -248 l 160 -256 l 115 -265 l 115 -396 l 115 -527 l 114 -531 b 95 -544 110 -539 102 -544 b 76 -531 87 -544 78 -539 l 73 -527 l 73 -399 b 73 -273 73 -330 73 -273 b 49 -277 73 -273 61 -274 b 17 -281 32 -280 24 -281 b 4 -276 10 -281 8 -280 b -1 -234 0 -269 -1 -272 b 0 -219 -1 -229 0 -224 l 0 -170 l 1 -167 b 10 -158 2 -163 6 -159 b 49 -149 13 -156 16 -155 l 73 -145 l 73 -34 b 73 76 73 26 73 76 b 49 72 73 76 61 74 b 17 68 32 69 24 68 b 4 73 10 68 8 69 b -1 115 0 80 -1 77 b 0 130 -1 120 0 124 l 0 179 l 1 181 b 10 191 2 186 6 190 b 49 199 13 192 16 194 l 73 204 l 73 338 b 73 374 73 352 73 365 b 77 483 73 484 73 477 b 95 492 81 489 88 492 b 111 483 100 492 107 489 b 115 378 115 477 115 483 l 115 342 b 117 212 115 223 115 212 b 204 229 117 212 200 227 l 205 229 l 205 365 l 205 502 l 206 505 b 225 517 210 513 219 517 b 245 505 234 517 242 513 l 246 502 l 247 369 l 247 237 l 249 237 b 336 254 253 238 336 254 b 337 390 336 254 337 302 l 337 526 l 338 530 b 352 541 341 535 347 539 m 336 15 b 336 126 336 102 336 126 l 336 126 b 291 117 336 126 315 122 l 247 109 l 247 -1 l 247 -112 l 249 -112 b 336 -95 253 -111 336 -95 b 336 15 336 -95 336 -56 m 205 -120 b 205 -55 205 -120 205 -93 b 205 -9 205 -41 205 -24 l 205 101 l 160 93 l 115 84 l 115 -26 b 115 -83 115 -49 115 -69 b 117 -137 115 -133 115 -137 b 205 -120 118 -137 204 -120 "},"v52":{"x_min":-10.890625,"x_max":298.078125,"ha":294,"o":"m 138 473 b 142 474 140 473 141 474 b 164 459 148 474 153 470 b 191 402 183 442 191 423 b 181 353 191 388 187 371 b 178 349 179 352 178 349 b 179 348 178 348 179 348 b 185 349 181 348 182 348 b 255 376 210 355 234 363 b 272 381 264 381 266 381 b 298 355 287 381 298 370 b 288 330 298 348 298 345 b 171 34 238 254 194 141 b 166 13 168 16 168 16 b 144 1 161 5 152 1 b 121 15 134 1 125 5 b 115 33 119 18 117 24 b 0 330 91 145 49 252 b -10 355 -9 345 -10 348 b 13 381 -10 371 0 381 b 31 376 19 381 25 380 b 132 345 61 358 103 345 l 136 345 l 137 355 b 145 378 138 359 142 370 b 152 415 149 394 152 405 b 137 452 152 427 148 438 b 133 464 134 458 133 460 b 138 473 133 467 134 470 "},"v54":{"x_min":-24.5,"x_max":317.140625,"ha":324,"o":"m -24 -161 l -24 -5 l -20 -5 b 0 -24 -9 -5 -2 -12 b 171 -315 21 -124 84 -233 b 317 -660 268 -406 317 -531 b 187 -1014 317 -782 274 -909 b 161 -1034 172 -1034 171 -1034 b 141 -1013 149 -1034 141 -1025 b 152 -991 141 -1004 142 -1002 b 266 -682 228 -899 266 -788 b 174 -430 266 -588 236 -498 b -23 -317 136 -388 66 -348 b -24 -161 -23 -316 -24 -285 "},"v55":{"x_min":0,"x_max":551.25,"ha":563,"o":"m 289 644 b 304 645 294 645 299 645 b 404 566 349 645 392 613 b 406 541 405 557 406 549 b 379 471 406 514 397 489 l 377 467 l 382 470 b 509 591 438 485 485 531 b 513 601 510 595 513 599 b 530 609 518 607 524 609 b 551 588 540 609 551 602 b 200 -605 551 584 204 -599 b 182 -616 197 -612 190 -616 b 163 -602 174 -616 166 -610 b 161 -598 161 -601 161 -601 b 217 -402 161 -589 170 -562 b 272 -213 247 -298 272 -213 b 272 -213 272 -213 272 -213 b 264 -219 272 -213 268 -216 b 140 -262 227 -247 182 -262 b 36 -226 102 -262 65 -249 b 0 -145 12 -206 0 -176 b 17 -84 0 -124 5 -104 b 103 -38 38 -54 70 -38 b 191 -91 137 -38 172 -56 b 205 -141 201 -106 205 -124 b 178 -212 205 -167 196 -194 l 175 -215 l 182 -213 b 307 -93 236 -198 284 -151 b 372 129 308 -88 372 127 b 372 129 372 129 372 129 b 364 122 372 129 368 126 b 240 80 328 94 283 80 b 137 115 202 80 166 91 b 99 195 112 136 99 165 b 118 256 99 217 106 238 b 204 303 138 287 171 303 b 292 249 238 303 273 285 b 306 199 302 234 306 217 b 279 129 306 173 296 148 l 276 126 l 281 127 b 408 248 336 142 385 190 b 473 470 409 254 473 469 b 473 470 473 470 473 470 b 465 464 473 470 469 467 b 341 421 428 435 383 421 b 236 458 303 421 266 433 b 200 537 212 478 200 508 b 289 644 200 585 234 635 "},"v58":{"x_min":-21.78125,"x_max":367.5,"ha":375,"o":"m 259 1553 b 265 1553 261 1553 264 1553 b 288 1540 272 1553 277 1550 b 367 1351 340 1493 367 1424 b 336 1221 367 1308 357 1263 l 332 1211 l 333 1208 b 367 1077 356 1170 367 1124 b 336 945 367 1032 357 986 l 332 935 l 333 932 b 367 800 356 893 367 848 b 336 669 367 756 357 710 l 332 659 l 333 656 b 367 523 356 617 367 571 b 345 412 367 485 360 446 b 231 273 322 356 284 310 b -1 19 121 195 27 93 b -17 4 -4 11 -10 5 l -21 4 l -21 134 l -21 265 l -17 265 b 133 291 20 265 96 278 b 318 537 245 328 318 433 b 307 603 318 559 315 582 b 303 614 304 612 304 614 b 298 609 302 614 300 613 b 231 549 281 589 258 567 b -1 295 121 471 27 369 b -17 280 -4 287 -10 281 l -21 280 l -21 410 l -21 541 l -17 541 b 133 567 20 541 96 555 b 318 813 245 605 318 709 b 307 880 318 835 315 859 b 303 891 304 888 304 891 b 298 885 302 891 300 888 b 231 825 281 866 258 843 b -1 571 121 748 27 645 b -17 556 -4 563 -10 557 l -21 556 l -21 687 l -21 817 l -17 817 b 133 843 20 817 96 830 b 318 1089 245 881 318 985 b 307 1156 318 1111 315 1134 b 303 1167 304 1164 304 1167 b 298 1161 302 1167 300 1164 b 231 1102 281 1140 258 1120 b -1 848 121 1024 27 921 b -17 832 -4 839 -10 834 l -21 832 l -21 963 l -21 1093 l -17 1093 b 114 1113 12 1093 78 1103 b 313 1314 215 1142 289 1218 b 318 1364 317 1331 318 1347 b 255 1511 318 1422 295 1478 b 243 1532 247 1519 243 1525 b 259 1553 243 1540 250 1550 "},"v59":{"x_min":0,"x_max":464.140625,"ha":474,"o":"m 0 0 l 0 347 l 76 347 l 153 347 l 153 0 l 153 -348 l 76 -348 l 0 -348 l 0 0 m 308 -1 l 308 347 l 386 347 l 464 347 l 464 -1 l 464 -348 l 386 -348 l 308 -348 l 308 -1 "},"v5b":{"x_min":-441,"x_max":439.640625,"ha":449,"o":"m -428 -2 b -421 0 -427 -1 -424 0 b -406 -6 -416 0 -409 -2 b -400 -31 -401 -12 -400 -15 b -1 -352 -392 -215 -215 -352 b 58 -349 19 -352 38 -351 b 398 -31 250 -326 392 -192 b 404 -6 398 -15 400 -12 b 419 -1 408 -2 413 -1 b 439 -13 427 -1 435 -5 b 439 -29 439 -16 439 -22 b 434 -105 439 -48 438 -80 b 0 -489 397 -333 213 -489 b -68 -484 -23 -489 -44 -488 b -441 -36 -280 -452 -436 -263 b -441 -30 -441 -34 -441 -31 b -428 -2 -441 -11 -439 -5 m -13 -9 b -1 -8 -9 -8 -5 -8 b 50 -36 19 -8 39 -19 b 61 -72 57 -47 61 -59 b 50 -106 61 -84 57 -97 b -1 -134 39 -124 19 -134 b -46 -115 -17 -134 -34 -129 b -62 -72 -57 -102 -62 -87 b -13 -9 -62 -44 -44 -16 "},"v5c":{"x_min":0,"x_max":447.8125,"ha":457,"o":"m 0 -87 l 0 0 l 223 0 l 447 0 l 447 -87 l 447 -174 l 223 -174 l 0 -174 l 0 -87 "},"v5d":{"x_min":-1.359375,"x_max":592.078125,"ha":604,"o":"m 280 692 b 295 694 283 692 289 694 b 310 692 300 694 307 692 b 357 630 340 684 357 657 b 336 580 357 612 351 594 b 311 538 321 566 311 549 b 352 492 311 512 330 492 b 366 495 357 492 362 492 b 397 553 390 503 397 517 b 415 603 397 576 402 591 b 460 623 427 617 443 623 b 509 599 479 623 498 614 b 522 559 518 587 522 573 b 494 506 522 538 513 519 b 451 495 481 498 473 496 b 415 488 432 495 426 494 b 394 449 404 483 394 464 b 394 448 394 448 394 448 l 394 440 l 397 433 b 428 409 404 420 413 413 b 438 408 431 408 435 408 b 479 431 450 408 462 415 b 528 455 495 448 510 455 b 548 452 534 455 541 453 b 592 391 577 442 592 416 b 549 331 592 365 577 340 b 528 327 541 328 534 327 b 479 351 510 327 495 335 b 438 374 464 367 450 374 b 417 369 431 374 424 373 b 394 333 402 360 394 348 b 400 312 394 326 396 319 b 451 287 408 294 420 288 b 513 258 484 285 499 278 b 522 223 519 247 522 234 b 461 159 522 190 496 159 b 449 161 457 159 453 159 b 397 229 416 167 397 191 b 366 288 397 265 390 278 b 352 290 362 290 357 290 b 315 262 336 290 321 280 b 311 245 313 256 311 251 b 334 204 311 233 318 220 b 355 170 348 190 351 184 b 357 152 356 166 357 159 b 355 136 357 147 356 140 b 295 88 345 104 321 88 b 232 152 264 88 232 112 b 255 204 232 174 238 186 b 279 244 273 222 279 231 l 279 245 b 238 290 279 270 259 290 b 224 288 234 290 228 290 b 193 229 200 278 193 265 b 141 161 193 191 174 167 b 129 159 137 159 133 159 b 68 223 93 159 68 190 b 77 258 68 234 70 247 b 138 287 91 278 106 285 b 185 302 166 287 175 291 b 196 333 193 312 196 323 b 174 369 196 347 187 360 b 152 374 166 373 159 374 b 111 351 140 374 126 367 b 62 327 95 335 80 327 b 51 328 58 327 54 327 b -1 391 16 334 -1 363 b 53 455 -1 420 17 449 b 62 455 57 455 59 455 b 111 431 80 455 95 448 b 152 408 127 415 140 408 b 161 409 155 408 159 408 b 193 433 176 413 186 420 l 196 440 l 196 448 b 196 451 196 449 196 449 b 190 471 196 459 194 463 b 137 495 182 489 167 495 l 134 495 l 134 495 b 68 560 95 495 68 521 b 129 623 68 596 95 623 b 144 621 134 623 138 623 b 193 553 175 614 193 589 b 224 495 193 517 200 503 b 238 492 228 492 234 492 b 279 538 259 492 279 512 b 254 580 279 549 269 566 b 232 630 239 594 232 612 b 280 692 232 657 250 684 m 307 456 b 295 458 303 458 299 458 b 230 391 258 458 230 426 b 236 360 230 381 231 371 b 295 324 249 337 272 324 b 353 360 318 324 341 337 b 360 391 357 370 360 381 b 307 456 360 421 340 451 "},"v62":{"x_min":46.28125,"x_max":669.671875,"ha":563,"o":"m 183 376 b 189 376 185 376 187 376 b 212 374 197 376 208 376 b 265 337 234 369 253 355 b 274 317 268 331 273 320 b 274 316 274 317 274 316 b 280 323 276 316 276 319 b 311 358 288 337 299 348 b 319 366 315 360 318 365 b 356 376 326 373 340 376 b 382 371 364 376 374 374 b 428 337 400 366 417 352 b 436 317 431 331 436 320 b 438 316 436 317 436 316 b 442 323 438 316 439 319 b 475 358 451 337 462 348 b 483 366 477 360 481 365 b 518 376 488 373 503 376 b 544 373 528 376 536 376 b 604 285 579 360 604 326 b 597 249 604 273 601 258 b 543 63 596 247 544 70 b 541 54 543 61 541 55 b 540 44 540 51 540 47 b 552 23 540 33 545 23 b 552 23 552 23 552 23 b 647 126 586 29 627 72 b 658 138 651 136 653 138 b 660 138 660 138 660 138 b 669 129 666 137 669 136 b 654 88 669 122 665 109 b 562 -12 631 43 602 9 l 549 -19 b 521 -27 540 -24 530 -27 b 447 30 490 -27 458 -4 b 443 58 445 38 443 48 b 450 93 443 72 446 84 b 504 278 453 97 504 272 b 507 288 506 283 506 287 b 509 298 507 292 509 295 b 491 326 509 310 502 320 b 487 327 490 327 488 327 b 479 324 484 327 483 326 b 441 270 462 316 443 288 b 435 249 441 265 436 254 b 398 127 434 248 419 195 b 362 4 379 61 362 5 b 328 -1 359 -1 362 -1 b 314 -1 323 -1 319 -1 b 302 -1 310 -1 306 -1 b 266 4 266 -1 269 -1 b 265 6 265 5 265 5 b 303 144 265 13 272 34 b 343 278 325 216 343 276 b 344 288 343 281 344 285 b 345 298 345 291 345 295 b 330 326 345 310 340 320 b 323 327 328 327 325 327 b 317 324 322 327 321 326 b 279 270 300 316 281 288 b 273 249 279 265 274 254 b 236 127 272 248 255 195 b 200 4 216 61 200 5 b 164 -1 197 -1 198 -1 b 151 -1 161 -1 156 -1 b 140 -1 147 -1 142 -1 b 103 4 104 -1 106 -1 b 103 6 103 5 103 5 b 141 144 103 13 108 34 b 181 278 161 216 179 276 b 182 288 181 281 181 285 b 183 298 182 291 183 295 b 168 324 183 310 178 320 b 160 327 166 326 163 327 b 141 320 156 327 151 324 b 69 230 112 305 85 272 b 57 215 65 217 62 215 b 55 215 57 215 55 215 b 46 224 49 215 46 217 b 59 260 46 231 50 242 b 151 363 81 306 112 341 b 161 369 155 365 160 367 b 183 376 166 371 174 374 "},"v68":{"x_min":-597.53125,"x_max":596.171875,"ha":608,"o":"m -533 324 b -525 327 -530 326 -528 327 b -504 305 -514 327 -504 317 b -504 305 -504 305 -504 305 b -513 284 -504 299 -504 299 b -556 112 -541 226 -556 167 b -545 33 -556 84 -552 58 b -524 -20 -541 15 -532 -9 l -522 -23 l -491 15 l -413 111 b -355 174 -367 169 -363 174 b -351 174 -353 174 -352 174 b -254 86 -343 174 -348 179 b -168 -1 -208 37 -168 -1 b -100 84 -168 -1 -137 37 b -23 173 -28 173 -29 172 b -19 174 -21 174 -20 174 b -8 173 -14 174 -10 173 b 155 11 -5 172 43 123 l 166 -1 l 168 1 l 170 4 l 170 130 b 171 260 170 256 170 258 b 191 274 175 269 183 274 b 205 267 196 274 201 272 b 212 158 212 262 210 273 l 212 56 l 257 112 b 311 173 304 172 304 172 b 317 174 313 174 314 174 b 326 173 319 174 323 173 b 490 11 329 172 366 134 l 502 -1 l 530 34 b 568 76 560 72 563 74 b 575 77 570 77 573 77 b 596 56 586 77 596 68 b 594 48 596 54 596 51 b 417 -172 592 41 424 -166 b 405 -176 415 -174 409 -176 b 396 -174 401 -176 398 -176 b 307 -87 393 -173 372 -152 b 221 -1 259 -38 221 -1 b 216 -6 221 -1 219 -2 l 212 -12 l 212 -147 b 212 -210 212 -173 212 -194 b 205 -292 212 -297 210 -287 b 191 -299 201 -297 196 -299 b 172 -287 183 -299 175 -295 b 170 -174 171 -284 171 -284 l 170 -63 l 127 -117 b 73 -176 84 -170 80 -176 b 68 -176 72 -176 70 -176 b -27 -87 59 -174 65 -180 b -114 0 -74 -38 -112 0 b -182 -86 -114 0 -145 -38 b -258 -174 -253 -174 -253 -173 b -264 -176 -259 -176 -262 -176 b -274 -174 -268 -176 -272 -174 b -438 -11 -277 -173 -348 -102 l -449 0 l -479 -37 b -524 -80 -513 -80 -514 -80 l -524 -80 b -553 -52 -534 -80 -540 -74 b -597 109 -583 -8 -597 48 b -560 280 -597 165 -585 224 b -533 324 -548 310 -540 322 "},"v6c":{"x_min":-1.359375,"x_max":193.28125,"ha":197,"o":"m 78 233 b 87 233 81 233 84 233 b 187 140 132 233 174 195 b 193 102 190 127 193 115 b 43 -113 193 22 136 -62 b 27 -119 36 -116 31 -119 b 19 -108 21 -119 19 -115 b 29 -97 19 -102 20 -101 b 102 13 73 -72 102 -27 b 92 51 102 26 98 40 l 91 54 l 84 54 b 8 104 53 54 21 74 b -1 142 1 116 -1 130 b 78 233 -1 187 31 227 "},"v6f":{"x_min":-80.3125,"x_max":78.9375,"ha":81,"o":"m 63 191 b 69 192 65 192 66 192 b 77 188 72 192 76 191 b 78 183 78 187 78 186 b 74 158 78 179 77 172 l 66 115 b 9 -161 49 30 10 -158 b -10 -187 6 -172 -1 -181 b -34 -194 -17 -191 -25 -194 b -80 -147 -58 -194 -80 -174 b -80 -141 -80 -144 -80 -142 b 9 70 -80 -134 -73 -117 l 49 163 b 63 191 59 188 61 190 "},"v70":{"x_min":0,"x_max":436.921875,"ha":446,"o":"m 213 190 b 217 191 215 191 216 191 b 231 184 223 191 228 188 b 249 154 240 167 246 159 b 419 18 292 91 348 45 b 436 -1 435 11 436 8 b 424 -16 436 -9 434 -13 b 308 -87 394 -26 340 -59 b 231 -186 276 -117 257 -142 b 219 -192 228 -191 225 -192 b 198 -174 209 -192 208 -191 b 47 -33 161 -113 110 -63 b 10 -16 34 -26 17 -19 b 0 -1 2 -13 0 -9 b 17 18 0 8 1 11 b 198 173 95 48 156 101 b 213 190 206 187 208 188 "},"v72":{"x_min":-423.3125,"x_max":421.9375,"ha":431,"o":"m -262 197 b -247 197 -257 197 -253 197 b -118 162 -210 197 -163 184 b 40 45 -61 134 -13 98 b 277 -95 119 -33 200 -81 b 289 -97 281 -97 285 -97 b 378 0 332 -97 371 -55 b 378 11 378 4 378 6 b 302 83 378 55 345 83 b 242 66 283 83 262 77 b 208 56 231 59 219 56 b 148 120 175 56 148 81 b 201 186 148 151 164 172 b 261 198 220 194 240 198 b 420 45 341 198 411 136 b 421 22 421 37 421 29 b 245 -199 421 -93 338 -199 b 238 -198 243 -199 240 -199 b -44 -47 148 -194 50 -141 b -250 86 -114 22 -183 66 b -295 94 -270 91 -283 94 b -315 91 -302 94 -307 94 b -381 4 -356 81 -381 43 b -355 -56 -381 -18 -372 -40 b -298 -81 -338 -73 -319 -81 b -246 -68 -283 -81 -265 -77 b -212 -58 -234 -61 -223 -58 b -178 -69 -200 -58 -189 -62 b -151 -122 -160 -81 -151 -101 b -171 -167 -151 -138 -157 -155 b -239 -195 -185 -181 -213 -192 b -257 -197 -245 -197 -250 -197 b -423 -5 -352 -197 -423 -109 b -412 65 -423 16 -419 40 b -262 197 -389 137 -329 188 "},"v74":{"x_min":-206.890625,"x_max":428.75,"ha":438,"o":"m 389 -351 b 394 -351 390 -351 393 -351 b 428 -385 413 -351 428 -367 b 428 -394 428 -388 428 -391 b 394 -428 426 -406 421 -410 l 332 -473 l 269 -516 l 205 -560 l 141 -603 l 77 -648 l 13 -692 l -50 -737 l -114 -780 l -145 -802 b -171 -813 -157 -810 -163 -813 b -175 -813 -172 -813 -174 -813 b -206 -777 -194 -811 -206 -795 b -202 -760 -206 -771 -205 -766 b -87 -675 -197 -752 -206 -757 l -34 -639 l 83 -557 l 145 -514 l 209 -470 l 272 -427 b 389 -351 375 -356 381 -352 "},"v75":{"x_min":-149.71875,"x_max":148.359375,"ha":151,"o":"m -137 381 b -130 383 -134 383 -133 383 b -111 371 -122 383 -114 378 b -55 224 -110 370 -85 305 b 0 80 -25 145 -1 80 b 54 224 0 80 24 145 b 112 377 114 384 110 373 b 127 384 118 381 122 384 b 148 362 138 384 148 374 l 148 356 l 83 183 b 16 9 47 88 17 11 b -1 0 12 2 5 0 b -14 5 -5 0 -10 1 b -84 183 -19 9 -13 -6 l -149 356 l -149 362 b -137 381 -149 371 -145 378 "},"v78":{"x_min":0,"x_max":193.28125,"ha":197,"o":"m 85 514 b 95 517 88 517 89 517 b 114 505 103 517 110 513 l 115 502 l 115 376 b 115 249 115 306 115 249 b 141 258 117 249 127 252 l 167 266 l 172 266 b 190 254 181 265 187 262 l 193 251 l 193 202 l 193 188 b 187 147 193 149 191 152 b 147 130 183 142 182 141 l 115 119 l 115 9 b 115 -99 115 -51 115 -99 b 141 -91 115 -99 127 -95 b 171 -81 166 -81 167 -81 l 171 -81 b 191 -94 181 -81 189 -87 b 193 -142 191 -97 193 -120 b 191 -195 193 -167 191 -194 b 125 -227 187 -205 187 -204 l 115 -230 l 115 -366 l 115 -503 l 114 -506 b 95 -519 110 -514 102 -519 b 74 -506 87 -519 78 -514 l 73 -503 l 73 -374 b 73 -245 73 -260 73 -245 b 73 -245 73 -245 73 -245 b 55 -252 72 -245 63 -249 l 32 -260 b 19 -263 27 -262 23 -263 b 4 -256 13 -263 8 -260 b 0 -215 0 -251 0 -254 b 0 -199 0 -210 0 -206 l 0 -152 l 1 -149 b 8 -140 2 -145 5 -141 b 42 -127 9 -140 24 -133 l 73 -116 l 73 -5 b 73 23 73 4 73 15 b 73 105 73 70 73 105 b 49 97 73 105 61 101 b 17 88 32 91 23 88 b 4 95 10 88 8 91 b 0 137 0 101 0 98 b 0 151 0 141 0 145 l 0 199 l 1 202 b 43 224 5 212 5 212 l 73 234 l 73 367 l 73 502 l 74 505 b 85 514 77 509 81 513 "},"v79":{"x_min":-1.359375,"x_max":899.703125,"ha":918,"o":"m 307 349 b 332 351 315 351 323 351 b 443 340 367 351 408 347 b 741 47 607 306 720 195 b 744 0 743 31 744 16 b 660 -303 744 -90 713 -206 b 28 -755 534 -531 304 -695 b 14 -756 23 -755 19 -756 b -1 -741 4 -756 -1 -750 b 21 -720 -1 -731 1 -728 b 567 -56 337 -601 548 -344 b 568 -11 568 -41 568 -24 b 442 285 568 129 525 233 b 325 319 406 308 367 319 b 93 177 232 319 137 266 b 84 154 91 170 84 155 b 84 154 84 154 84 154 b 88 156 84 154 85 155 b 159 177 110 170 134 177 b 257 134 194 177 231 162 b 294 41 281 108 294 73 b 171 -97 294 -24 246 -90 b 156 -98 166 -97 161 -98 b 6 74 73 -98 6 -22 b 6 80 6 76 6 79 b 307 349 10 223 141 340 m 839 215 b 845 216 841 216 842 216 b 862 213 852 216 860 215 b 899 163 887 206 899 184 b 872 117 899 145 890 127 b 847 111 865 112 856 111 b 808 130 833 111 818 117 b 796 162 800 140 796 151 b 839 215 796 187 812 212 m 839 -112 b 845 -112 841 -112 842 -112 b 862 -115 852 -112 860 -113 b 899 -165 887 -122 899 -144 b 872 -210 899 -183 890 -201 b 847 -217 865 -215 856 -217 b 808 -198 833 -217 818 -210 b 796 -165 800 -188 796 -177 b 839 -112 796 -140 812 -116 "},"v7c":{"x_min":0,"x_max":300.8125,"ha":307,"o":"m 49 505 b 53 506 50 505 51 506 b 70 496 58 506 62 503 b 81 485 73 492 78 488 l 96 473 l 111 459 l 122 449 l 134 438 l 182 396 l 255 330 b 292 291 292 298 292 298 l 292 290 l 292 284 l 283 270 b 209 36 234 197 209 113 b 288 -170 209 -44 235 -119 b 299 -184 295 -179 299 -181 b 300 -191 300 -187 300 -188 b 285 -206 300 -199 294 -206 b 280 -206 283 -206 281 -206 b 247 -201 270 -202 259 -201 b 176 -222 223 -201 197 -208 b 114 -340 136 -249 114 -292 b 172 -471 114 -384 134 -433 b 185 -492 182 -481 185 -487 b 181 -502 185 -496 183 -499 b 171 -508 176 -505 174 -508 b 152 -498 166 -508 160 -503 b 0 -284 65 -428 12 -352 b 0 -260 0 -278 0 -270 b 1 -238 0 -252 0 -242 b 148 -140 16 -177 73 -140 b 209 -148 167 -140 189 -142 b 215 -149 212 -148 215 -149 b 215 -149 215 -149 215 -149 l 215 -149 b 201 -136 215 -148 209 -142 l 157 -97 l 96 -41 b 17 34 21 24 17 29 b 17 37 17 36 17 36 b 17 38 17 37 17 38 b 25 56 17 44 17 44 b 110 298 81 131 110 219 b 46 474 110 367 88 431 b 38 491 40 480 38 487 b 49 505 38 498 42 502 "},"v7d":{"x_min":-1.359375,"x_max":436.921875,"ha":446,"o":"m 213 205 b 217 205 215 205 216 205 b 234 194 224 205 234 199 b 236 187 234 194 235 190 l 245 167 l 261 129 l 270 106 b 355 -61 294 54 329 -13 b 420 -163 381 -105 402 -138 b 436 -188 435 -184 436 -184 b 436 -191 436 -190 436 -190 b 421 -206 436 -201 431 -206 l 421 -206 l 416 -206 l 405 -201 b 217 -158 347 -172 283 -158 b 31 -201 153 -158 88 -172 l 20 -206 l 14 -206 l 14 -206 b 0 -191 5 -206 0 -201 b -1 -188 0 -190 -1 -190 b 14 -163 -1 -186 0 -184 b 95 -34 36 -136 72 -77 b 166 106 119 8 148 68 l 175 129 l 183 148 l 200 188 b 213 205 205 199 208 202 "},"v7f":{"x_min":0,"x_max":367.5,"ha":375,"o":"m 0 124 l 0 187 l 61 187 l 122 187 l 122 138 l 122 91 l 153 61 l 183 30 l 213 61 l 243 91 l 243 138 l 243 187 l 306 187 l 367 187 l 367 124 l 367 61 l 321 61 l 274 61 l 243 30 l 213 0 l 243 -31 l 274 -62 l 321 -62 l 367 -62 l 367 -124 l 367 -188 l 306 -188 l 243 -188 l 243 -140 l 243 -93 l 213 -62 l 183 -31 l 153 -62 l 122 -93 l 122 -140 l 122 -188 l 61 -188 l 0 -188 l 0 -124 l 0 -62 l 46 -62 l 92 -62 l 123 -31 l 153 0 l 123 30 l 92 61 l 46 61 l 0 61 l 0 124 "},"v80":{"x_min":29.9375,"x_max":420.578125,"ha":371,"o":"m 115 345 b 221 347 117 345 166 347 b 411 345 306 347 409 345 b 420 330 416 342 420 335 b 415 319 420 326 419 321 b 178 118 397 303 179 118 b 178 117 178 118 178 117 b 181 117 178 117 178 117 b 189 117 182 117 185 117 b 193 117 190 117 191 117 b 247 98 215 117 232 111 b 296 75 266 83 280 76 b 302 75 299 75 300 75 b 322 91 311 75 315 79 b 322 91 322 91 322 91 b 322 91 322 91 322 91 b 319 91 322 91 321 91 b 313 90 318 90 315 90 b 283 107 300 90 288 97 b 277 126 279 114 277 121 b 319 167 277 149 295 167 b 319 167 319 167 319 167 b 362 118 347 167 362 147 b 355 82 362 108 359 96 b 311 33 349 65 340 55 b 224 1 284 12 253 1 b 194 5 213 1 204 2 b 168 18 183 8 178 11 b 110 36 151 30 130 36 b 57 15 88 36 68 29 b 47 11 54 12 51 11 b 31 20 40 11 34 13 b 29 26 31 22 29 25 b 68 66 29 36 39 45 b 285 250 73 71 281 248 b 285 250 285 250 285 250 b 231 252 285 252 261 252 b 137 250 190 252 141 250 b 93 227 122 248 110 241 b 78 220 88 222 83 220 b 66 227 74 220 70 222 b 63 234 65 229 63 231 b 85 291 63 241 69 252 b 115 345 108 342 108 344 "},"v81":{"x_min":0,"x_max":428.75,"ha":438,"o":"m 262 186 b 273 186 266 186 272 186 b 274 186 273 186 274 186 b 285 186 274 186 280 186 b 428 48 375 181 428 122 b 386 -68 428 12 416 -29 b 155 -187 329 -145 236 -187 b 12 -111 92 -187 38 -162 b 0 -51 4 -91 0 -72 b 262 186 0 58 122 179 m 366 131 b 352 134 362 133 357 134 b 219 81 321 134 269 115 b 47 -111 126 23 50 -62 b 47 -112 47 -111 47 -112 b 77 -136 47 -129 58 -136 b 264 -45 118 -136 194 -101 b 382 109 336 12 382 76 b 366 131 382 120 377 129 "},"v83":{"x_min":-1.359375,"x_max":847.96875,"ha":865,"o":"m 488 1499 b 495 1500 490 1500 492 1500 b 541 1465 507 1500 521 1490 b 679 1078 622 1372 679 1210 b 677 1050 679 1068 677 1060 b 477 642 668 893 604 764 l 443 609 l 431 596 l 431 592 l 438 562 l 449 508 l 460 458 b 481 355 475 390 481 355 b 481 355 481 355 481 355 b 490 356 481 355 485 355 b 528 358 495 356 511 358 b 558 356 540 358 552 356 b 839 95 699 338 808 237 b 847 22 845 72 847 47 b 631 -303 847 -113 766 -242 b 620 -309 623 -308 620 -309 l 620 -310 b 631 -359 620 -310 626 -333 l 646 -435 l 660 -496 b 672 -588 668 -535 672 -563 b 664 -653 672 -610 669 -630 b 383 -875 630 -792 509 -875 b 201 -810 321 -875 257 -855 b 129 -680 151 -768 129 -730 b 274 -530 129 -592 200 -530 b 351 -553 300 -530 326 -538 b 412 -669 393 -582 412 -626 b 287 -805 412 -735 366 -800 l 279 -805 l 285 -809 b 383 -830 318 -823 351 -830 b 586 -718 464 -830 540 -789 b 626 -584 612 -678 626 -631 b 619 -528 626 -566 623 -548 b 612 -495 619 -526 616 -510 b 577 -324 590 -387 577 -324 b 577 -324 577 -324 577 -324 b 568 -326 575 -324 571 -324 b 528 -334 558 -328 537 -333 b 465 -338 506 -337 485 -338 b 24 -11 269 -338 87 -206 b -1 145 8 41 -1 93 b 96 442 -1 249 32 351 b 322 714 166 541 236 626 l 352 745 l 345 782 l 332 843 l 315 921 b 303 984 310 950 304 978 b 295 1082 298 1017 295 1049 b 413 1426 295 1208 336 1329 b 488 1499 436 1456 477 1496 m 549 1301 b 541 1301 547 1301 544 1301 b 411 1207 500 1301 447 1263 b 355 1004 374 1152 355 1079 b 359 942 355 984 356 963 b 371 881 362 927 363 917 l 385 818 b 392 782 389 799 392 784 l 392 782 b 434 828 393 782 424 816 b 607 1165 534 941 594 1060 b 608 1193 608 1175 608 1183 b 597 1270 608 1224 604 1254 b 549 1301 589 1286 571 1299 m 398 528 b 393 555 396 542 393 553 b 392 555 393 555 393 555 b 317 470 390 555 347 505 b 190 298 266 408 212 334 b 127 70 148 227 127 148 b 155 -77 127 19 137 -30 b 468 -303 209 -216 333 -303 b 519 -299 484 -303 502 -302 b 568 -284 541 -295 568 -287 l 568 -284 b 563 -263 568 -284 566 -274 l 534 -120 l 511 -13 l 496 61 l 480 133 b 469 187 472 176 469 187 b 468 188 469 187 469 188 b 416 162 462 188 430 172 b 337 13 364 126 337 69 b 413 -124 337 -40 363 -93 b 428 -144 424 -131 428 -137 b 428 -149 428 -145 428 -148 b 409 -166 426 -161 419 -166 b 394 -162 405 -166 400 -165 b 240 77 302 -122 240 -27 l 240 77 b 430 342 240 197 315 301 l 436 344 l 426 394 l 398 528 m 548 194 b 526 195 540 195 532 195 b 519 195 524 195 521 195 l 514 195 l 518 177 l 539 79 l 552 15 l 566 -48 l 594 -187 l 605 -240 b 612 -266 609 -254 611 -266 b 612 -266 612 -266 612 -266 b 641 -248 613 -266 630 -256 b 744 -98 692 -212 730 -156 b 751 -40 749 -79 751 -59 b 548 194 751 76 665 181 "},"v84":{"x_min":25.859375,"x_max":164.6875,"ha":168,"o":"m 34 369 b 40 370 35 370 38 370 b 59 353 49 370 50 367 b 164 40 122 254 155 158 b 164 0 164 33 164 16 b 164 -40 164 -16 164 -34 b 59 -353 155 -158 122 -254 b 40 -371 53 -366 47 -371 b 34 -370 38 -371 36 -370 b 25 -358 28 -367 25 -363 b 31 -337 25 -352 27 -347 b 92 0 72 -234 92 -117 b 31 335 92 116 72 233 b 25 356 27 345 25 352 b 34 369 25 363 28 366 "},"v86":{"x_min":-571.671875,"x_max":570.3125,"ha":582,"o":"m -386 173 b -381 174 -385 174 -383 174 b -370 173 -377 174 -372 173 b -281 86 -367 172 -347 151 b -196 0 -235 37 -196 0 b -126 84 -196 0 -164 37 b -50 174 -55 173 -57 172 b -44 174 -49 174 -47 174 b -35 173 -42 174 -38 173 b 53 86 -32 172 -12 151 b 138 0 100 37 138 0 b 208 84 140 0 170 37 b 284 174 279 173 277 172 b 289 174 285 174 288 174 b 299 173 294 174 298 173 b 462 11 303 172 338 134 l 475 -1 l 503 34 b 541 76 534 72 536 74 b 548 77 544 77 545 77 b 570 56 560 77 570 68 b 567 48 570 54 568 51 b 392 -172 564 41 397 -166 b 378 -176 387 -174 382 -176 b 368 -174 374 -176 371 -176 b 280 -87 367 -173 345 -152 b 194 0 234 -38 194 0 b 125 -86 194 0 163 -38 b 49 -174 54 -174 55 -173 b 43 -176 47 -176 46 -176 b 34 -174 40 -176 36 -174 b -54 -87 31 -173 10 -152 b -140 0 -102 -38 -140 0 b -209 -86 -141 0 -171 -38 b -285 -174 -280 -174 -279 -173 b -291 -176 -287 -176 -289 -176 b -300 -174 -295 -176 -299 -174 b -464 -12 -304 -173 -340 -137 l -476 0 l -504 -34 b -543 -77 -534 -73 -537 -76 b -549 -79 -545 -79 -547 -79 b -571 -58 -562 -79 -571 -69 b -568 -49 -571 -55 -570 -52 b -392 172 -566 -43 -396 167 b -386 173 -390 172 -387 173 "},"v8b":{"x_min":0,"x_max":319.859375,"ha":326,"o":"m 149 508 b 159 509 152 509 155 509 b 186 494 170 509 181 503 b 190 440 190 487 190 488 l 190 430 l 190 377 l 242 377 l 251 377 b 303 373 298 377 296 377 b 319 345 314 367 319 356 b 304 319 319 335 314 324 b 250 315 296 315 299 315 l 242 315 l 190 315 l 190 262 l 190 252 b 186 198 190 204 190 205 b 159 183 179 188 170 183 b 132 198 148 183 138 188 b 127 252 127 205 127 204 l 127 262 l 127 315 l 76 315 l 68 315 b 14 319 20 315 21 315 b 0 347 4 324 0 335 b 14 373 0 356 4 367 b 68 377 21 377 20 377 l 76 377 l 127 377 l 127 430 l 127 440 b 132 494 127 488 127 487 b 149 508 136 501 142 505 "},"v8c":{"x_min":-330.75,"x_max":329.390625,"ha":336,"o":"m -133 483 b -117 484 -127 484 -122 484 b 31 373 -51 484 9 440 b 35 348 34 365 35 356 b -25 285 35 313 10 285 b -87 331 -55 285 -76 302 b -167 402 -100 376 -133 402 b -191 398 -175 402 -183 401 b -227 341 -215 388 -227 369 b -225 320 -227 334 -227 327 b -13 74 -209 230 -125 133 b 6 65 -4 70 5 66 l 9 63 l 10 65 b 117 231 12 68 40 112 l 189 341 l 242 424 b 268 460 262 456 264 458 b 283 464 273 463 277 464 b 308 438 296 464 308 453 l 308 437 b 287 396 308 430 308 428 l 95 98 l 59 43 l 58 41 l 65 37 b 253 -156 151 -8 217 -77 b 281 -285 272 -199 281 -244 b 148 -481 281 -381 231 -463 b 115 -485 137 -484 126 -485 b -32 -376 51 -485 -9 -442 b -36 -349 -35 -366 -36 -358 b 25 -287 -36 -315 -12 -287 b 85 -333 54 -287 74 -302 b 166 -403 99 -377 133 -403 b 190 -399 174 -403 182 -402 b 225 -342 215 -390 225 -370 b 224 -322 225 -335 225 -328 b 12 -76 208 -231 125 -134 b -8 -66 2 -72 -6 -68 l -10 -65 l -12 -66 b -118 -231 -13 -68 -42 -113 l -190 -342 l -243 -426 b -269 -462 -264 -458 -265 -458 b -284 -466 -274 -464 -279 -466 b -310 -440 -298 -466 -310 -455 l -310 -438 b -288 -398 -310 -430 -308 -430 l -96 -99 l -59 -44 l -59 -43 l -66 -38 b -281 284 -198 33 -281 158 l -281 284 b -133 483 -281 392 -220 474 m 254 177 b 266 179 258 177 262 179 b 319 149 287 179 307 167 b 329 115 326 140 329 127 b 319 79 329 102 326 90 b 268 51 307 61 287 51 b 221 72 250 51 234 58 b 205 115 210 84 205 99 b 254 177 205 142 223 170 m -281 -54 b -269 -52 -277 -52 -273 -52 b -223 -73 -253 -52 -235 -59 b -206 -116 -212 -84 -206 -101 b -216 -151 -206 -129 -209 -141 b -269 -179 -228 -170 -249 -179 b -314 -159 -285 -179 -302 -173 b -330 -116 -325 -147 -330 -131 b -281 -54 -330 -88 -313 -61 "},"v8f":{"x_min":-21.78125,"x_max":362.0625,"ha":369,"o":"m 302 1031 b 308 1032 304 1032 307 1032 b 330 1016 318 1032 325 1027 b 362 867 351 970 362 920 b 340 738 362 824 353 780 l 336 727 l 340 717 b 362 591 355 677 362 634 b 257 323 362 496 325 401 b 204 272 243 306 227 290 b 20 56 129 206 66 133 b -1 18 12 44 0 22 b -19 4 -4 9 -12 4 l -21 4 l -21 140 l -21 276 l -12 277 b 167 333 61 288 127 309 b 319 598 262 388 319 491 b 311 664 319 620 317 642 l 310 673 l 304 664 b 204 548 279 620 250 587 b 20 333 129 483 66 409 b -1 292 12 320 0 298 b -19 280 -4 285 -12 280 l -21 280 l -21 416 l -21 552 l -12 553 b 167 609 61 564 127 585 b 319 874 264 666 319 770 b 294 992 319 914 311 954 b 288 1011 288 1004 288 1007 b 302 1031 288 1021 294 1028 "},"v90":{"x_min":-171.5,"x_max":483.1875,"ha":493,"o":"m -8 631 b -1 632 -6 632 -4 632 b 19 620 8 632 16 628 b 20 495 20 616 20 616 b 20 373 20 427 20 373 b 115 410 20 373 63 390 l 210 448 l 210 531 b 212 620 210 614 210 616 b 231 632 215 628 223 632 b 246 627 236 632 242 631 b 251 541 251 620 251 628 l 251 463 l 315 489 b 387 514 368 509 381 514 b 393 513 390 514 392 514 b 406 494 402 510 406 502 b 397 476 406 487 404 480 b 323 446 396 474 363 462 l 251 417 l 251 283 l 251 148 l 254 151 b 370 199 291 183 332 199 b 415 191 385 199 400 197 b 483 84 458 176 483 134 b 461 0 483 58 476 29 b 332 -142 439 -40 411 -72 l 255 -215 b 231 -229 240 -229 239 -229 b 216 -223 224 -229 220 -227 b 210 -158 210 -217 210 -223 b 210 -120 210 -148 210 -136 l 210 -29 l 205 -34 b 100 -142 182 -65 159 -88 l 23 -215 b -1 -229 9 -229 6 -229 b -19 -217 -9 -229 -16 -224 l -20 -215 l -21 48 l -21 310 l -83 287 b -152 262 -133 266 -145 262 b -157 263 -153 262 -155 262 b -171 283 -166 266 -171 274 b -161 301 -171 290 -167 297 b -91 328 -160 302 -129 315 l -21 356 l -21 487 l -20 617 l -19 621 b -8 631 -17 626 -12 630 m 210 288 b 210 401 210 351 210 401 b 114 365 209 401 167 384 l 20 327 l 20 238 l 20 148 l 21 151 b 140 199 59 183 102 199 b 206 180 164 199 187 192 l 209 177 b 209 177 209 177 209 177 b 210 288 210 177 210 199 m 110 131 b 96 133 106 133 100 133 b 89 133 93 133 91 133 b 24 87 63 129 40 113 l 20 80 l 20 -37 l 20 -156 l 23 -152 b 144 81 96 -72 144 20 l 144 83 b 110 131 144 113 134 126 m 341 131 b 328 133 337 133 332 133 b 322 133 326 133 323 133 b 257 87 296 129 273 113 l 251 80 l 251 -37 l 251 -156 l 255 -152 b 375 81 328 -72 375 20 l 375 83 b 341 131 375 113 367 126 "},"v92":{"x_min":0,"x_max":598.890625,"ha":611,"o":"m 62 181 b 77 183 66 183 72 183 b 91 181 83 183 88 183 b 202 131 100 180 106 177 l 299 87 l 394 131 b 517 183 499 181 502 183 b 519 183 517 183 518 183 b 598 104 567 183 598 144 b 577 49 598 84 592 65 b 518 15 567 38 563 37 b 484 0 499 6 484 0 b 518 -16 484 -1 499 -8 b 577 -51 563 -38 567 -40 b 598 -105 592 -66 598 -86 b 519 -184 598 -145 567 -184 b 517 -184 518 -184 517 -184 b 394 -133 502 -184 499 -183 l 299 -88 l 202 -133 b 81 -184 99 -183 95 -184 b 77 -184 80 -184 78 -184 b 0 -105 29 -184 0 -145 b 20 -51 0 -86 5 -66 b 80 -16 29 -40 34 -38 b 114 -1 98 -8 114 -1 b 80 15 114 0 98 6 b 20 49 34 37 29 38 b 0 104 6 65 0 84 b 62 181 0 140 23 174 m 88 134 b 74 136 85 134 80 136 b 68 134 72 136 69 136 b 46 104 54 130 46 117 b 55 81 46 95 49 88 b 149 34 59 76 53 80 b 224 -1 190 15 224 0 b 144 -38 224 -1 187 -18 b 54 -84 59 -79 58 -79 b 46 -105 49 -90 46 -98 b 76 -137 46 -122 58 -137 b 78 -137 77 -137 77 -137 b 194 -86 87 -137 76 -141 b 298 -36 250 -58 298 -36 b 298 -36 298 -36 298 -36 b 402 -84 299 -36 345 -58 b 518 -137 522 -141 510 -137 b 521 -137 519 -137 519 -137 b 551 -105 539 -137 551 -122 b 541 -83 551 -98 548 -90 b 447 -36 537 -77 544 -81 b 374 -1 406 -16 374 -1 b 447 34 374 0 406 15 b 541 81 544 80 537 76 b 551 104 548 88 551 97 b 521 136 551 120 539 136 b 518 136 519 136 519 136 b 517 136 518 136 517 136 l 517 136 b 402 83 511 136 511 136 b 298 34 345 56 299 34 b 298 34 298 34 298 34 b 194 84 298 34 250 56 b 88 134 137 111 89 133 "},"v93":{"x_min":0,"x_max":438.28125,"ha":447,"o":"m 212 205 b 219 205 213 205 216 205 b 239 183 228 205 231 204 b 421 -163 298 40 363 -83 b 438 -191 434 -180 438 -186 b 436 -197 438 -192 438 -195 b 424 -206 434 -204 431 -206 b 406 -201 420 -206 415 -205 b 216 -156 347 -172 281 -156 b 23 -205 148 -156 80 -173 b 14 -206 20 -206 17 -206 b 0 -191 6 -206 0 -201 b 6 -176 0 -187 1 -183 b 202 192 63 -104 142 45 b 212 205 205 199 208 202 m 264 48 l 249 81 l 243 94 l 242 91 b 89 -126 208 36 137 -66 b 81 -138 85 -133 81 -138 b 81 -138 81 -138 81 -138 b 81 -138 81 -138 81 -138 b 95 -133 81 -138 87 -136 b 280 -94 156 -108 221 -94 b 334 -98 299 -94 317 -95 b 343 -99 338 -99 343 -99 b 343 -99 343 -99 343 -99 b 338 -94 343 -99 341 -97 b 264 48 318 -58 287 1 "},"v94":{"x_min":-149.71875,"x_max":148.359375,"ha":151,"o":"m -9 215 b 0 217 -6 217 -4 217 b 19 205 8 217 14 213 b 20 142 20 202 20 201 l 20 84 l 23 84 b 144 -27 81 74 129 30 b 148 -66 147 -40 148 -54 b 36 -213 148 -134 103 -197 b 0 -219 24 -217 12 -219 b -145 -104 -68 -219 -129 -173 b -149 -68 -148 -91 -149 -79 b -24 84 -149 6 -98 74 l -21 84 l -21 142 b -19 205 -20 201 -20 202 b -9 215 -17 209 -13 213 m -21 -15 b -23 41 -21 37 -21 41 b -23 41 -23 41 -23 41 b -76 11 -35 40 -62 26 b -108 -65 -98 -11 -108 -38 b -1 -176 -108 -122 -65 -176 b 107 -65 63 -176 107 -122 b 74 11 107 -38 96 -11 b 20 41 61 26 32 41 b 20 -15 20 41 20 15 b 19 -74 20 -72 20 -72 b 0 -87 14 -83 6 -87 b -19 -74 -8 -87 -16 -83 b -21 -15 -20 -72 -20 -72 "},"v95":{"x_min":0,"x_max":406.96875,"ha":415,"o":"m 55 181 b 70 183 61 183 66 183 b 111 170 85 183 99 179 b 160 130 115 167 137 149 l 202 95 l 245 130 b 319 181 299 176 302 179 b 334 183 325 183 330 183 b 406 109 375 183 406 148 b 401 81 406 99 405 91 b 348 24 394 65 390 59 b 318 -1 332 11 318 0 b 348 -26 318 -1 332 -12 b 401 -83 390 -61 394 -66 b 406 -111 405 -93 406 -101 b 334 -184 406 -149 375 -184 b 319 -183 330 -184 325 -184 b 245 -131 302 -180 299 -177 l 202 -97 l 160 -131 b 85 -183 107 -177 103 -180 b 70 -184 80 -184 76 -184 b 0 -111 31 -184 0 -149 b 4 -83 0 -101 1 -93 b 58 -26 10 -66 16 -61 b 88 -1 74 -12 88 -1 b 58 24 88 0 74 11 b 10 69 23 54 17 59 b 0 109 2 81 0 95 b 55 181 0 142 21 173 m 83 133 b 72 136 78 136 76 136 b 57 131 66 136 61 134 b 46 109 49 126 46 117 b 50 93 46 104 47 98 b 107 45 51 91 77 70 b 160 0 137 20 160 0 b 107 -47 160 -1 137 -22 b 50 -94 77 -72 51 -93 b 46 -111 47 -99 46 -105 b 59 -134 46 -120 50 -130 b 72 -137 62 -136 68 -137 b 83 -136 76 -137 80 -136 b 144 -84 84 -134 107 -116 b 202 -36 176 -58 202 -36 b 261 -84 202 -36 230 -58 b 323 -136 299 -116 321 -134 b 334 -137 326 -136 330 -137 b 345 -134 338 -137 343 -136 b 360 -111 355 -130 360 -120 b 355 -94 360 -105 359 -99 b 299 -47 353 -93 329 -72 b 245 0 269 -22 245 -1 b 299 45 245 0 269 20 b 355 93 329 70 353 91 b 360 109 359 98 360 104 b 345 133 360 119 355 129 b 334 136 343 134 338 136 b 323 134 330 136 326 134 b 261 83 321 133 299 115 b 202 34 230 56 202 34 b 144 83 202 34 176 56 b 83 133 106 115 84 133 "},"v97":{"x_min":-228.671875,"x_max":227.3125,"ha":232,"o":"m -217 487 l -213 488 l 0 488 l 212 488 l 216 487 b 225 476 220 484 224 480 l 227 473 l 227 244 l 227 15 l 225 12 b 206 0 223 4 215 0 b 197 1 204 0 200 0 b 187 12 193 4 189 6 l 186 15 l 186 138 l 186 262 l -1 262 l -187 262 l -187 138 l -187 15 l -189 12 b -208 0 -193 4 -200 0 b -227 12 -216 0 -223 4 l -228 15 l -228 244 l -228 473 l -227 476 b -217 487 -225 480 -221 484 "},"v9a":{"x_min":-21.78125,"x_max":367.5,"ha":375,"o":"m 230 1031 b 238 1032 232 1032 235 1032 b 259 1014 245 1032 251 1027 b 367 662 330 906 367 782 b 364 602 367 641 367 621 b 232 317 352 488 304 384 b 57 120 155 245 103 187 b -1 18 31 84 6 40 b -19 4 -4 11 -12 4 l -21 4 l -21 159 l -21 315 l -16 315 b 96 335 10 315 62 324 b 315 695 227 380 315 527 b 313 738 315 709 314 724 b 224 991 304 825 273 916 b 216 1013 219 999 216 1007 b 230 1031 216 1021 220 1028 "},"v9b":{"x_min":-24.5,"x_max":313.0625,"ha":319,"o":"m -24 -133 l -24 -5 l -20 -5 b -1 -19 -12 -5 -4 -11 b 142 -213 13 -61 74 -144 b 258 -376 196 -269 230 -315 b 313 -605 295 -449 313 -528 b 292 -742 313 -652 306 -699 b 288 -752 289 -748 288 -752 b 288 -752 288 -752 288 -752 b 292 -764 289 -753 291 -757 b 313 -907 306 -811 313 -860 b 292 -1045 313 -954 306 -1002 b 288 -1054 289 -1050 288 -1054 b 288 -1054 288 -1054 288 -1054 b 292 -1067 289 -1054 291 -1060 b 313 -1210 306 -1113 313 -1161 b 292 -1346 313 -1257 306 -1304 b 288 -1357 289 -1353 288 -1357 b 288 -1357 288 -1357 288 -1357 b 292 -1368 289 -1357 291 -1363 b 313 -1512 306 -1415 313 -1464 b 292 -1648 313 -1560 306 -1605 b 288 -1660 289 -1654 288 -1660 b 288 -1660 288 -1660 288 -1660 b 292 -1671 289 -1660 291 -1665 b 313 -1814 306 -1719 313 -1766 b 250 -2040 313 -1897 291 -1977 b 232 -2062 238 -2057 236 -2059 b 221 -2065 230 -2063 225 -2065 b 200 -2045 210 -2065 201 -2057 b 200 -2043 200 -2044 200 -2044 b 208 -2026 200 -2037 202 -2034 b 269 -1826 249 -1966 269 -1897 b 153 -1544 269 -1726 230 -1625 b -9 -1472 115 -1506 58 -1481 b -21 -1471 -14 -1471 -19 -1471 l -24 -1471 l -24 -1343 l -24 -1215 l -20 -1215 b -1 -1229 -12 -1215 -4 -1221 b 142 -1424 13 -1270 74 -1353 b 257 -1582 196 -1478 228 -1524 b 264 -1594 261 -1589 264 -1594 l 264 -1594 b 265 -1582 264 -1594 264 -1589 b 270 -1525 268 -1562 270 -1544 b 153 -1243 270 -1424 228 -1321 b -9 -1170 115 -1203 58 -1178 b -21 -1168 -14 -1170 -19 -1168 l -24 -1168 l -24 -1041 l -24 -913 l -20 -913 b -1 -927 -12 -913 -4 -918 b 142 -1121 13 -967 74 -1050 b 257 -1281 196 -1175 228 -1221 b 264 -1292 261 -1286 264 -1292 l 264 -1292 b 265 -1279 264 -1292 264 -1286 b 270 -1222 268 -1261 270 -1242 b 153 -941 270 -1121 228 -1018 b -9 -867 115 -900 58 -875 b -21 -866 -14 -867 -19 -866 l -24 -866 l -24 -738 l -24 -610 l -20 -610 b -1 -624 -12 -610 -4 -616 b 142 -818 13 -664 74 -749 b 257 -978 196 -873 228 -918 b 264 -989 261 -984 264 -989 l 264 -989 b 265 -977 264 -989 264 -984 b 270 -920 268 -959 270 -939 b 153 -638 270 -818 228 -716 b -9 -564 115 -598 58 -573 b -21 -563 -14 -564 -19 -563 l -24 -563 l -24 -435 l -24 -308 l -20 -308 b -1 -322 -12 -308 -4 -313 b 142 -516 13 -363 74 -446 b 257 -675 196 -571 228 -616 b 264 -687 261 -681 264 -687 l 264 -687 b 265 -674 264 -687 264 -681 b 270 -617 268 -656 270 -637 b 153 -335 270 -516 228 -413 b -9 -262 115 -295 58 -270 b -21 -260 -14 -262 -19 -260 l -24 -260 l -24 -133 "},"v9c":{"x_min":-166.0625,"x_max":-25.859375,"ha":0,"o":"m -49 369 b -42 370 -46 369 -44 370 b -27 360 -36 370 -29 366 b -25 355 -27 359 -25 358 b -32 335 -25 351 -28 347 b -92 52 -66 248 -87 159 b -93 -1 -93 43 -93 20 b -92 -54 -93 -23 -93 -45 b -32 -337 -85 -162 -66 -251 b -25 -355 -27 -349 -25 -352 b -42 -371 -25 -365 -32 -371 b -61 -353 -50 -371 -51 -369 b -163 -63 -119 -262 -153 -165 b -166 -1 -166 -37 -166 -31 b -163 62 -166 30 -166 36 b -61 352 -153 163 -119 260 b -49 369 -54 365 -51 366 "},"v9e":{"x_min":0,"x_max":607.0625,"ha":619,"o":"m 243 631 b 250 632 246 632 249 632 b 270 620 259 632 268 628 l 272 616 l 272 201 l 272 -212 l 270 -216 b 251 -229 268 -224 259 -229 b 227 -215 243 -229 240 -229 l 151 -142 b 32 -16 81 -80 53 -49 b 0 84 9 18 0 52 b 111 199 0 149 42 199 b 137 197 119 199 127 198 b 228 151 168 191 197 177 l 231 148 l 231 383 b 232 620 231 616 231 616 b 243 631 234 624 238 630 m 168 131 b 152 133 163 133 157 133 b 107 102 130 133 111 120 b 106 86 107 97 106 91 b 111 41 106 73 108 56 b 227 -152 125 -13 171 -90 l 231 -156 l 231 -37 l 231 80 l 225 87 b 168 131 210 111 190 126 m 347 631 b 353 632 348 632 351 632 b 374 620 363 632 371 628 b 375 383 375 616 375 616 l 375 148 l 377 151 b 492 199 415 183 454 199 b 537 191 507 199 522 197 b 607 84 582 176 607 134 b 583 0 607 58 598 29 b 455 -142 562 -40 533 -72 l 378 -215 b 355 -229 364 -229 362 -229 b 334 -216 345 -229 337 -224 l 333 -212 l 333 201 l 333 616 l 334 620 b 347 631 337 624 341 630 m 465 131 b 451 133 461 133 455 133 b 445 133 449 133 446 133 b 379 87 419 129 396 113 l 375 80 l 375 -37 l 375 -156 l 378 -152 b 499 81 451 -72 499 20 l 499 83 b 465 131 499 113 490 126 "},"va3":{"x_min":58.53125,"x_max":228.671875,"ha":294,"o":"m 138 371 b 142 373 140 371 141 373 b 178 342 149 373 156 366 b 228 251 217 297 228 278 b 228 244 228 248 228 247 b 176 147 227 212 212 184 b 123 73 152 122 132 93 b 121 62 122 70 121 66 b 145 13 121 48 129 31 b 153 -2 151 6 153 1 b 149 -9 153 -5 152 -6 b 144 -11 148 -11 145 -11 b 129 -1 140 -11 136 -8 b 61 87 89 37 68 68 b 58 113 59 95 58 105 b 110 215 58 144 74 177 b 163 287 134 240 155 269 b 166 299 166 291 166 295 b 141 348 166 313 157 330 b 133 360 134 356 133 358 b 133 363 133 362 133 362 b 138 371 133 367 136 370 "},"va5":{"x_min":0,"x_max":349.8125,"ha":357,"o":"m 88 302 b 103 303 93 302 98 303 b 202 224 149 303 191 270 b 205 199 204 216 205 208 b 178 129 205 173 196 147 l 175 126 l 182 127 b 307 249 236 142 284 190 b 313 259 308 254 311 258 b 329 267 317 265 323 267 b 349 247 340 267 349 259 b 201 -263 349 242 204 -258 b 182 -273 197 -270 190 -273 b 163 -260 174 -273 166 -269 b 161 -256 161 -259 161 -258 b 217 -59 161 -248 170 -220 b 272 129 247 43 272 127 b 272 129 272 129 272 129 b 264 122 272 129 268 126 b 140 80 227 94 183 80 b 36 115 102 80 65 91 b 0 194 10 136 0 165 b 88 302 0 244 32 292 "},"va9":{"x_min":-24.5,"x_max":314.421875,"ha":321,"o":"m -24 -145 l -24 -5 l -20 -5 b 0 -23 -9 -5 -2 -12 b 27 -87 4 -38 14 -66 b 138 -220 53 -136 88 -177 b 235 -328 179 -255 208 -288 b 314 -592 287 -409 314 -501 b 292 -732 314 -639 307 -687 l 289 -742 l 294 -756 b 314 -896 307 -802 314 -849 b 292 -1035 314 -943 307 -991 l 289 -1045 l 294 -1057 b 314 -1197 307 -1104 314 -1152 b 292 -1338 314 -1246 307 -1292 l 289 -1347 l 294 -1360 b 314 -1500 307 -1407 314 -1454 b 273 -1689 314 -1565 300 -1628 b 250 -1712 265 -1710 261 -1712 b 228 -1691 236 -1712 228 -1704 l 228 -1685 l 234 -1675 b 270 -1507 258 -1621 270 -1564 b 98 -1193 270 -1381 209 -1261 b 40 -1174 76 -1179 58 -1174 b -10 -1189 24 -1174 8 -1178 b -20 -1192 -14 -1192 -16 -1192 l -24 -1192 l -24 -1052 l -24 -913 l -20 -913 b 0 -931 -9 -913 -2 -920 b 27 -995 4 -946 14 -974 b 138 -1128 53 -1043 88 -1085 b 257 -1275 190 -1172 228 -1220 b 262 -1283 259 -1279 262 -1283 l 262 -1283 b 269 -1249 264 -1282 268 -1260 b 270 -1206 270 -1233 270 -1220 b 98 -891 270 -1075 206 -957 b 40 -871 76 -877 58 -871 b -10 -886 24 -871 8 -875 b -20 -889 -14 -889 -16 -889 l -24 -889 l -24 -749 l -24 -610 l -20 -610 b 0 -628 -9 -610 -2 -617 b 27 -692 4 -644 14 -671 b 138 -825 53 -741 88 -782 b 257 -973 190 -870 228 -917 b 262 -981 259 -977 262 -981 l 262 -981 b 269 -946 264 -979 268 -957 b 270 -903 270 -931 270 -917 b 98 -588 270 -774 206 -655 b 40 -569 76 -574 58 -569 b -10 -584 24 -569 8 -574 b -20 -587 -14 -587 -16 -587 l -24 -587 l -24 -448 l -24 -308 l -20 -308 b 0 -326 -9 -308 -2 -315 b 27 -390 4 -341 14 -369 b 138 -523 53 -438 88 -480 b 257 -670 190 -567 228 -614 b 262 -678 259 -674 262 -678 b 262 -678 262 -678 262 -678 b 269 -644 264 -677 268 -656 b 270 -601 270 -628 270 -614 b 98 -285 270 -471 206 -352 b 40 -266 76 -273 58 -266 b -10 -281 24 -266 8 -272 b -20 -284 -14 -284 -16 -284 l -24 -284 l -24 -145 "},"vaa":{"x_min":-1.359375,"x_max":752.703125,"ha":768,"o":"m 490 985 b 504 986 495 986 500 986 b 604 907 551 986 593 954 b 607 884 607 900 607 892 b 581 813 607 857 597 831 l 578 810 l 583 811 b 710 932 638 827 687 873 b 714 943 711 936 713 942 b 730 952 720 949 725 952 b 752 931 741 952 752 943 b 200 -946 752 927 204 -941 b 182 -957 197 -953 190 -957 b 163 -945 174 -957 166 -953 b 161 -939 161 -942 161 -942 b 217 -743 161 -931 170 -904 b 272 -555 247 -639 272 -555 b 272 -555 272 -555 272 -555 b 264 -560 272 -555 268 -557 b 140 -603 227 -589 182 -603 b 36 -567 102 -603 65 -592 b -1 -487 12 -548 -1 -517 b 17 -427 -1 -466 5 -445 b 103 -380 38 -395 70 -380 b 191 -433 137 -380 172 -398 b 205 -484 201 -448 205 -466 b 178 -553 205 -509 196 -535 l 175 -557 l 182 -555 b 307 -435 236 -539 284 -494 b 372 -213 308 -430 372 -215 b 372 -213 372 -213 372 -213 b 364 -219 372 -213 368 -216 b 240 -262 328 -247 283 -262 b 137 -226 202 -262 166 -249 b 99 -145 112 -206 99 -176 b 118 -84 99 -124 106 -104 b 204 -38 138 -54 171 -38 b 292 -91 238 -38 273 -56 b 306 -141 302 -106 306 -124 b 279 -212 306 -167 296 -194 l 276 -215 l 281 -213 b 408 -93 336 -198 385 -151 b 473 129 409 -88 473 127 b 473 129 473 129 473 129 b 465 122 473 129 469 126 b 341 80 428 94 383 80 b 236 115 303 80 266 91 b 200 195 213 136 200 165 b 217 256 200 217 206 238 b 304 303 239 287 272 303 b 393 249 338 303 374 285 b 406 199 402 234 406 217 b 379 129 406 173 397 148 l 377 126 l 382 127 b 509 248 436 142 485 190 b 574 470 510 254 574 469 b 574 470 574 470 574 470 b 566 464 574 470 570 467 b 442 421 529 435 484 421 b 337 458 404 421 367 433 b 300 538 314 477 300 508 b 318 598 300 559 306 580 b 404 645 340 630 372 645 b 494 592 439 645 475 627 b 507 541 502 577 507 559 b 480 471 507 516 498 489 l 477 467 l 483 470 b 608 589 537 485 586 531 b 675 811 611 595 675 810 b 675 811 675 811 675 811 b 666 806 675 811 671 809 b 543 763 628 777 585 763 b 438 799 504 763 468 775 b 401 878 412 820 401 849 b 490 985 401 928 434 977 "},"vab":{"x_min":0,"x_max":272.21875,"ha":278,"o":"m 243 631 b 250 632 246 632 249 632 b 270 620 259 632 268 628 l 272 616 l 272 201 l 272 -212 l 270 -216 b 251 -229 268 -224 259 -229 b 227 -215 243 -229 240 -229 l 151 -142 b 32 -16 81 -80 53 -49 b 0 84 9 18 0 52 b 111 199 0 149 42 199 b 137 197 119 199 127 198 b 228 151 168 191 197 177 l 231 148 l 231 383 b 232 620 231 616 231 616 b 243 631 234 624 238 630 m 168 131 b 152 133 163 133 157 133 b 107 102 130 133 111 120 b 106 86 107 97 106 91 b 111 41 106 73 108 56 b 227 -152 125 -13 171 -90 l 231 -156 l 231 -37 l 231 80 l 225 87 b 168 131 210 111 190 126 "},"vad":{"x_min":0,"x_max":873.828125,"ha":892,"o":"m 0 0 l 0 703 l 81 703 l 164 703 l 164 0 l 164 -705 l 81 -705 l 0 -705 l 0 0 m 225 0 l 225 703 l 246 703 l 268 703 l 268 366 l 268 30 l 274 36 b 314 79 284 44 302 63 b 413 302 357 137 392 213 b 432 327 419 324 421 327 b 449 306 443 327 447 322 b 611 115 457 195 529 115 b 651 122 624 115 638 117 b 728 316 705 140 724 188 b 729 388 728 342 729 366 b 671 635 729 533 711 602 b 581 662 649 652 616 662 b 477 637 545 662 510 653 l 475 635 l 477 634 b 503 627 488 632 495 631 b 545 556 532 612 545 584 b 491 480 545 524 526 491 b 465 474 481 476 473 474 b 379 563 417 474 379 516 b 389 602 379 576 382 588 b 541 691 409 641 479 681 b 582 694 555 692 568 694 b 865 462 714 694 834 598 b 873 392 871 440 873 416 b 865 317 873 367 871 341 b 639 84 839 194 748 101 b 612 83 630 83 620 83 b 511 116 577 83 543 94 b 504 120 509 119 506 120 b 504 120 504 120 504 120 b 469 59 504 120 488 93 l 432 -1 l 469 -61 b 504 -122 488 -94 504 -122 b 504 -122 504 -122 504 -122 b 511 -117 506 -122 509 -120 b 612 -84 543 -95 577 -84 b 665 -91 630 -84 647 -87 b 869 -338 771 -122 850 -216 b 873 -392 872 -356 873 -374 b 798 -595 873 -469 847 -539 b 581 -695 741 -662 660 -695 b 406 -626 517 -695 454 -671 b 381 -563 389 -607 381 -585 b 465 -477 381 -519 413 -477 b 545 -559 514 -477 545 -519 b 503 -628 545 -587 532 -613 b 477 -635 495 -632 488 -634 l 475 -637 l 477 -638 b 581 -663 510 -655 545 -663 b 671 -637 616 -663 649 -653 b 729 -391 711 -603 729 -534 b 728 -317 729 -367 728 -344 b 623 -117 722 -173 698 -124 b 611 -116 619 -116 615 -116 b 449 -308 528 -116 457 -198 b 432 -328 447 -323 443 -328 b 413 -303 421 -328 419 -326 b 314 -80 392 -215 357 -138 b 274 -37 302 -65 284 -45 l 268 -31 l 268 -367 l 268 -705 l 246 -705 l 225 -705 l 225 0 "},"vb3":{"x_min":0,"x_max":227.3125,"ha":232,"o":"m 91 213 b 100 215 93 215 96 215 b 227 58 167 215 224 144 b 227 52 227 56 227 54 b 61 -201 227 -43 164 -138 b 29 -216 44 -212 36 -216 b 23 -210 27 -216 24 -213 b 21 -205 21 -208 21 -206 b 34 -192 21 -201 25 -197 b 122 -55 89 -161 122 -106 b 104 6 122 -33 117 -12 l 103 9 l 96 9 b 4 79 57 9 17 38 b 0 112 1 90 0 101 b 91 213 0 163 36 209 "},"vb6":{"x_min":0,"x_max":556.6875,"ha":568,"o":"m 289 545 b 298 546 292 545 295 546 b 318 533 306 546 315 541 b 319 428 319 530 319 528 l 319 327 l 334 327 b 526 223 412 326 485 285 b 543 172 537 206 543 190 b 447 76 543 122 503 76 b 445 76 446 76 446 76 b 359 165 394 77 359 119 b 368 205 359 179 362 192 b 441 251 382 233 412 251 b 455 249 446 251 451 251 b 460 248 458 249 460 248 b 460 248 460 248 460 248 b 454 254 460 249 458 251 b 334 295 419 280 378 294 l 319 295 l 319 4 l 319 -287 l 321 -285 b 328 -285 322 -285 325 -285 b 524 -99 424 -277 507 -198 b 541 -79 526 -84 530 -79 b 556 -97 551 -79 556 -84 b 548 -133 556 -105 553 -117 b 334 -317 521 -233 434 -306 b 322 -319 329 -317 323 -317 l 319 -319 l 319 -424 b 319 -471 319 -444 319 -459 b 313 -541 319 -544 318 -535 b 298 -548 308 -545 303 -548 b 279 -534 289 -548 281 -542 b 277 -424 277 -531 277 -530 l 277 -317 l 273 -317 b 13 -95 153 -305 51 -217 b 0 2 4 -62 0 -29 b 182 295 0 126 66 238 b 274 324 210 309 249 320 l 277 324 l 277 427 b 279 533 277 528 277 530 b 289 545 281 538 285 542 m 277 2 b 277 291 277 161 277 291 b 268 288 277 291 273 290 b 144 1 179 265 144 184 b 276 -284 144 -199 175 -267 l 277 -285 l 277 2 "},"vb9":{"x_min":-122.5,"x_max":121.140625,"ha":124,"o":"m -16 145 b 0 147 -10 147 -5 147 b 121 -1 66 147 121 77 b 114 -49 121 -16 118 -33 b -1 -148 95 -112 47 -148 b -85 -106 -31 -148 -61 -134 b -122 -1 -110 -76 -122 -38 b -16 145 -122 68 -81 134 m 12 111 b 0 113 8 113 4 113 b -68 22 -29 113 -61 73 b -70 0 -69 15 -70 6 b -13 -113 -70 -49 -47 -98 b -1 -115 -9 -115 -5 -115 b 63 -40 24 -115 53 -83 b 68 -1 66 -27 68 -15 b 12 111 68 48 46 97 "},"vba":{"x_min":-118.421875,"x_max":597.53125,"ha":381,"o":"m 460 574 b 464 574 461 574 462 574 b 488 574 470 574 481 574 b 500 573 491 574 498 574 b 594 503 543 570 588 538 b 597 488 596 498 597 494 b 528 417 597 449 564 417 b 502 423 519 417 510 419 b 465 481 477 434 465 458 b 488 528 465 499 472 516 b 490 530 490 530 490 530 b 490 530 490 530 490 530 b 468 517 488 530 475 523 b 349 340 419 485 377 420 b 347 330 348 334 347 330 b 383 328 347 328 363 328 b 428 326 423 328 424 328 b 442 302 438 320 442 312 b 430 281 442 294 438 285 b 385 276 424 277 426 276 l 377 276 l 332 276 l 330 269 b 178 -117 303 126 250 -9 b 1 -249 129 -194 69 -237 b -20 -251 -6 -251 -13 -251 b -114 -187 -65 -251 -100 -227 b -118 -156 -117 -177 -118 -166 b -51 -84 -118 -116 -91 -84 b -31 -87 -46 -84 -39 -86 b 16 -152 0 -95 16 -124 b -12 -205 16 -173 8 -194 b -16 -208 -14 -206 -16 -208 b -14 -208 -16 -208 -14 -208 b -9 -206 -14 -208 -12 -208 b 74 -124 23 -197 54 -166 b 172 224 98 -79 125 22 b 185 276 178 252 183 274 b 185 276 185 276 185 276 b 141 276 185 276 181 276 b 91 280 96 276 96 276 b 77 302 83 285 77 294 b 91 326 77 312 83 320 b 148 328 95 328 96 328 l 198 330 l 202 341 b 460 574 249 473 351 566 "},"vbf":{"x_min":-53.078125,"x_max":513.140625,"ha":485,"o":"m 185 383 b 196 384 187 383 191 384 b 277 334 230 384 259 365 b 288 301 281 324 288 306 b 288 297 288 298 288 297 b 294 302 289 297 291 299 b 394 370 323 338 367 367 b 404 371 398 370 401 371 b 510 272 453 371 498 328 b 513 237 513 262 513 251 b 507 172 513 217 511 192 b 326 -34 487 59 412 -26 b 314 -36 322 -36 318 -36 b 274 -24 298 -36 283 -31 l 265 -16 b 224 44 246 -1 232 20 b 223 49 224 47 223 49 b 223 49 223 49 223 49 b 149 -197 221 48 149 -194 b 149 -198 149 -197 149 -198 b 170 -210 149 -202 155 -205 b 187 -215 174 -210 175 -212 b 204 -231 201 -219 204 -222 b 197 -245 204 -240 202 -242 l 194 -248 l 76 -248 l -42 -248 l -46 -245 b -53 -231 -51 -242 -53 -240 b -35 -215 -53 -222 -49 -217 b -13 -210 -21 -212 -20 -212 b -6 -208 -10 -209 -8 -208 b 0 -206 -6 -208 -2 -206 b 25 -188 13 -201 21 -195 b 163 280 28 -183 163 276 b 166 291 163 283 164 287 b 167 302 167 295 167 299 b 155 324 167 315 161 324 b 155 324 155 324 155 324 b 65 230 125 322 85 280 b 53 215 61 217 58 215 b 51 215 53 215 51 215 b 42 224 46 215 42 217 b 57 263 42 231 47 244 b 140 360 77 305 104 337 b 152 370 144 365 149 369 b 185 383 157 376 172 381 m 374 306 b 366 308 371 308 368 308 b 300 273 348 308 321 294 b 284 254 288 262 287 259 b 280 242 283 249 281 245 b 257 169 279 240 270 213 l 236 98 l 236 93 b 251 48 238 77 243 61 b 279 27 258 37 272 27 b 281 27 279 27 280 27 b 291 31 281 27 287 30 b 396 170 334 52 378 109 b 406 247 402 197 406 224 b 401 277 406 259 405 270 b 374 306 397 290 383 303 "},"vc3":{"x_min":-10.890625,"x_max":299.4375,"ha":294,"o":"m 136 460 b 142 462 137 462 140 462 b 166 449 152 462 161 456 b 171 428 168 446 168 445 b 288 131 194 322 238 209 b 298 115 295 120 296 117 b 299 106 298 112 299 109 b 273 81 299 91 287 81 b 255 86 268 81 261 83 b 155 116 225 104 183 116 l 152 116 l 149 108 b 141 83 148 102 144 91 b 134 48 137 69 134 58 b 149 9 134 34 140 24 b 153 -1 152 5 153 1 b 149 -9 153 -5 152 -6 b 144 -11 148 -11 147 -11 b 122 2 138 -11 133 -6 b 95 61 104 20 95 38 b 107 108 95 74 99 90 b 108 113 107 111 108 112 b 107 113 108 113 108 113 b 102 113 106 113 104 113 b 31 86 76 108 53 98 b 14 80 24 81 20 80 b -10 106 0 80 -10 91 b 0 131 -10 115 -9 116 b 115 430 49 209 91 317 b 136 460 119 451 123 456 "}},"cssFontWeight":"normal","ascender":1903,"underlinePosition":-125,"cssFontStyle":"normal","boundingBox":{"yMin":-2065.375,"xMin":-695.53125,"yMax":1901.578125,"xMax":1159.671875},"resolution":1000,"descender":-2066,"familyName":"VexFlow-18","lineHeight":4093,"underlineThickness":50};// Vex Flow
// Mohit Muthanna <mohit@muthanna.com>
//
// Copyright Mohit Muthanna 2010
//
// Requires a glyph font to be loaded and Vex.Flow.Font to be set.

/**
 * A quick and dirty static glyph renderer. Renders glyphs from the default
 * font defined in Vex.Flow.Font.
 *
 * @param {!Object} ctx The canvas context.
 * @param {number} x_pos X coordinate.
 * @param {number} y_pos Y coordinate.
 * @param {number} point The point size to use.
 * @param {string} val The glyph code in Vex.Flow.Font.
 * @param {boolean} nocache If set, disables caching of font outline.
 */
Vex.Flow.renderGlyph = function(ctx, x_pos, y_pos, point, val, nocache) {
  var scale = point * 72.0 / (Vex.Flow.Font.resolution * 100.0);
  var metrics = Vex.Flow.Glyph.loadMetrics(Vex.Flow.Font, val, !nocache);
  Vex.Flow.Glyph.renderOutline(ctx, metrics.outline, scale, x_pos, y_pos);
};

/**
 * @constructor
 */
Vex.Flow.Glyph = (function() {
  function Glyph(code, point, options) {
    this.code = code;
    this.point = point;
    this.context = null;
    this.options = {
      cache: true,
      font: Vex.Flow.Font
    };

    this.width = null;
    this.metrics = null;
    this.x_shift = 0;
    this.y_shift = 0;

    if (options) this.setOptions(options); else this.reset();
  }

  Glyph.prototype = {
    setOptions: function(options) {
      Vex.Merge(this.options, options);
      this.reset();
    },

    setStave: function(stave) { this.stave = stave; return this; },
    setXShift: function(x_shift) { this.x_shift = x_shift; return this; },
    setYShift: function(y_shift) { this.y_shift = y_shift; return this; },
    setContext: function(context) { this.context = context; return this; },
    getContext: function() { return this.context; },

    reset: function() {
      this.metrics = Vex.Flow.Glyph.loadMetrics(this.options.font, this.code,
          this.options.cache);
      this.scale = this.point * 72 / (this.options.font.resolution * 100);
    },

    getMetrics: function() {
      if (!this.metrics) throw new Vex.RuntimeError("BadGlyph", "Glyph " +
          this.code + " is not initialized.");
      return {
        x_min: this.metrics.x_min * this.scale,
        x_max: this.metrics.x_max * this.scale,
        width: (this.metrics.x_max - this.metrics.x_min) * this.scale,
        height: this.metrics.ha * this.scale
      };
    },

    render: function(ctx, x_pos, y_pos) {
      if (!this.metrics) throw new Vex.RuntimeError("BadGlyph", "Glyph " +
          this.code + " is not initialized.");

      var outline = this.metrics.outline;
      var scale = this.scale;

      Glyph.renderOutline(ctx, outline, scale, x_pos, y_pos);
    },

    renderToStave: function(x) {
      if (!this.metrics) throw new Vex.RuntimeError("BadGlyph", "Glyph " +
          this.code + " is not initialized.");
      if (!this.stave) throw new Vex.RuntimeError("GlyphError", "No valid stave");
      if (!this.context) throw new Vex.RERR("GlyphError", "No valid context");

      var outline = this.metrics.outline;
      var scale = this.scale;

      Glyph.renderOutline(this.context, outline, scale,
          x + this.x_shift, this.stave.getYForGlyphs() + this.y_shift);
    }
  };

  /* Static methods used to implement loading / unloading of glyphs */
  Glyph.loadMetrics = function(font, code, cache) {
    var glyph = font.glyphs[code];
    if (!glyph) throw new Vex.RuntimeError("BadGlyph", "Glyph " + code +
        " does not exist in font.");

    var x_min = glyph.x_min;
    var x_max = glyph.x_max;
    var ha = glyph.ha;

    var outline;

    if (glyph.o) {
      if (cache) {
        if (glyph.cached_outline) {
          outline = glyph.cached_outline;
        } else {
          outline = glyph.o.split(' ');
          glyph.cached_outline = outline;
        }
      } else {
        if (glyph.cached_outline) delete glyph.cached_outline;
        outline = glyph.o.split(' ');
      }

      return {
        x_min: x_min,
        x_max: x_max,
        ha: ha,
        outline: outline
      };
    } else {
      throw new Vex.RuntimeError("BadGlyph", "Glyph " + this.code +
          " has no outline defined.");
    }
  };

  Glyph.renderOutline = function(ctx, outline, scale, x_pos, y_pos) {
    var outlineLength = outline.length;

    ctx.beginPath();

    ctx.moveTo(x_pos, y_pos);

    for (var i = 0; i < outlineLength; ) {
      var action = outline[i++];

      switch(action) {
        case 'm':
          ctx.moveTo(x_pos + outline[i++] * scale,
                     y_pos + outline[i++] * -scale);
          break;
        case 'l':
          ctx.lineTo(x_pos + outline[i++] * scale,
                     y_pos + outline[i++] * -scale);
          break;

        case 'q':
          var cpx = x_pos + outline[i++] * scale;
          var cpy = y_pos + outline[i++] * -scale;

          ctx.quadraticCurveTo(
              x_pos + outline[i++] * scale,
              y_pos + outline[i++] * -scale, cpx, cpy);
          break;

        case 'b':
          var x = x_pos + outline[i++] * scale;
          var y = y_pos + outline[i++] * -scale;

          ctx.bezierCurveTo(
              x_pos + outline[i++] * scale, y_pos + outline[i++] * -scale,
              x_pos + outline[i++] * scale, y_pos + outline[i++] * -scale,
              x, y);
          break;
      }
    }
    ctx.fill();
  };

  return Glyph;
}());
// Vex Flow
// Mohit Muthanna <mohit@muthanna.com>
//
// Copyright Mohit Cheppudira 2010

/** @constructor */
Vex.Flow.Stave = (function() {
  function Stave(x, y, width, options) {
    if (arguments.length > 0) this.init(x, y, width, options);
  }

  var THICKNESS = (Vex.Flow.STAVE_LINE_THICKNESS > 1 ?
        Vex.Flow.STAVE_LINE_THICKNESS : 0);
  Stave.prototype = {
    init: function(x, y, width, options) {
      this.x = x;
      this.y = y;
      this.width = width;
      this.glyph_start_x = x + 5;
      this.glyph_end_x = x + width;
      this.start_x = this.glyph_start_x;
      this.end_x = this.glyph_end_x;
      this.context = null;
      this.glyphs = [];
      this.end_glyphs = [];
      this.modifiers = [];  // non-glyph stave items (barlines, coda, segno, etc.)
      this.measure = 0;
      this.clef = "treble";
      this.font = {
        family: "sans-serif",
        size: 8,
        weight: ""
      };
      this.options = {
        vertical_bar_width: 10,       // Width around vertical bar end-marker
        glyph_spacing_px: 10,
        num_lines: 5,
        fill_style: "#999999",
        spacing_between_lines_px: 10, // in pixels
        space_above_staff_ln: 4,      // in staff lines
        space_below_staff_ln: 4,      // in staff lines
        top_text_position: 1          // in staff lines
      };
      this.bounds = {x: this.x, y: this.y, w: this.width, h: 0};
      Vex.Merge(this.options, options);

      this.resetLines();

      this.modifiers.push(
          new Vex.Flow.Barline(Vex.Flow.Barline.type.SINGLE, this.x)); // beg bar
      this.modifiers.push(
          new Vex.Flow.Barline(Vex.Flow.Barline.type.SINGLE,
          this.x + this.width)); // end bar
    },

    resetLines: function() {
      this.options.line_config = [];
      for (var i = 0; i < this.options.num_lines; i++) {
        this.options.line_config.push({visible: true});
      }
      this.height = (this.options.num_lines + this.options.space_above_staff_ln) *
         this.options.spacing_between_lines_px;
      this.options.bottom_text_position = this.options.num_lines + 1;
    },

    setNoteStartX: function(x) { this.start_x = x; return this; },
    getNoteStartX: function() {
      var start_x = this.start_x;

      // Add additional space if left barline is REPEAT_BEGIN and there are other
      // start modifiers than barlines
      if (this.modifiers[0].barline == Vex.Flow.Barline.type.REPEAT_BEGIN && 
          this.modifiers.length > 2)
        start_x += 20;
      return start_x;
    },

    getNoteEndX: function() { return this.end_x; },
    getTieStartX: function() { return this.start_x; },
    getTieEndX: function() { return this.x + this.width; },
    setContext: function(context) { this.context = context; return this; },
    getContext: function() { return this.context; },
    getX: function() { return this.x; },
    getNumLines: function() { return this.options.num_lines; },
    setNumLines: function(lines) {
      this.options.num_lines = parseInt(lines, 10);
      this.resetLines();
      return this;
    },
    setY: function(y) { this.y = y; return this; },

    setWidth: function(width) {
      this.width = width;
      this.glyph_end_x = this.x + width;
      this.end_x = this.glyph_end_x;

      // reset the x position of the end barline
      this.modifiers[1].setX(this.end_x);
      return this;
    },

    getWidth: function() {
      return this.width;
    },

    setMeasure: function(measure) { this.measure = measure; return this; },

      // Bar Line functions
    setBegBarType: function(type) {
      // Only valid bar types at beginning of stave is none, single or begin repeat
      if (type == Vex.Flow.Barline.type.SINGLE ||
          type == Vex.Flow.Barline.type.REPEAT_BEGIN ||
          type == Vex.Flow.Barline.type.NONE) {
          this.modifiers[0] = new Vex.Flow.Barline(type, this.x);
      }
      return this;
    },

    setEndBarType: function(type) {
      // Repeat end not valid at end of stave
      if (type != Vex.Flow.Barline.type.REPEAT_BEGIN)
        this.modifiers[1] = new Vex.Flow.Barline(type, this.x + this.width);
      return this;
    },

    /**
     * Gets the pixels to shift from the beginning of the stave
     * following the modifier at the provided index
     * @param  {Number} index The index from which to determine the shift
     * @return {Number}       The amount of pixels shifted
     */
    getModifierXShift: function(index) {
      if (typeof index === 'undefined') index = this.glyphs.length -1;
      if (typeof index !== 'number') new Vex.RERR("InvalidIndex",
        "Must be of number type");

      var x = this.glyph_start_x;
      var bar_x_shift = 0;

      for (var i = 0; i < index + 1; ++i) {
        var glyph = this.glyphs[i];
        x += glyph.getMetrics().width;
        bar_x_shift += glyph.getMetrics().width;
      }

      // Add padding after clef, time sig, key sig
      if (bar_x_shift > 0) bar_x_shift += this.options.vertical_bar_width + 10;

      return bar_x_shift;
    },

    // Coda & Segno Symbol functions
    setRepetitionTypeLeft: function(type, y) {
      this.modifiers.push(new Vex.Flow.Repetition(type, this.x, y));
      return this;
    },

    setRepetitionTypeRight: function(type, y) {
      this.modifiers.push(new Vex.Flow.Repetition(type, this.x, y) );
      return this;
    },

    // Volta functions
    setVoltaType: function(type, number_t, y) {
      this.modifiers.push(new Vex.Flow.Volta(type, number_t, this.x, y));
      return this;
    },

    // Section functions
    setSection: function(section, y) {
      this.modifiers.push(new Vex.Flow.StaveSection(section, this.x, y));
      return this;
    },

    // Tempo functions
    setTempo: function(tempo, y) {
      this.modifiers.push(new Vex.Flow.StaveTempo(tempo, this.x, y));
      return this;
    },

    // Text functions
    setText: function(text, position, options) {
      this.modifiers.push(new Vex.Flow.StaveText(text, position, options));
      return this;
    },

    getHeight: function() {
      return this.height;
    },

    getSpacingBetweenLines: function() {
      return this.options.spacing_between_lines_px;
    },

    getBoundingBox: function() {
      return new Vex.Flow.BoundingBox(this.x, this.y, this.width, this.getBottomY() - this.y);
      // body...
    },

    getBottomY: function() {
      var options = this.options;
      var spacing = options.spacing_between_lines_px;
      var score_bottom = this.getYForLine(options.num_lines) +
         (options.space_below_staff_ln * spacing);

      return score_bottom;
    },

    getBottomLineY: function() {
      return this.getYForLine(this.options.num_lines);
    },

    getYForLine: function(line) {
      var options = this.options;
      var spacing = options.spacing_between_lines_px;
      var headroom = options.space_above_staff_ln;

      var y = this.y + ((line * spacing) + (headroom * spacing)) -
        (THICKNESS / 2);

      return y;
    },

    getYForTopText: function(line) {
      var l = line || 0;
      return this.getYForLine(-l - this.options.top_text_position);
    },

    getYForBottomText: function(line) {
      var l = line || 0;
      return this.getYForLine(this.options.bottom_text_position + l);
    },

    getYForNote: function(line) {
      var options = this.options;
      var spacing = options.spacing_between_lines_px;
      var headroom = options.space_above_staff_ln;
      var y = this.y + (headroom * spacing) + (5 * spacing) - (line * spacing);

      return y;
    },

    getYForGlyphs: function() {
      return this.getYForLine(3);
    },

    addGlyph: function(glyph) {
      glyph.setStave(this);
      this.glyphs.push(glyph);
      this.start_x += glyph.getMetrics().width;
      return this;
    },

    addEndGlyph: function(glyph) {
      glyph.setStave(this);
      this.end_glyphs.push(glyph);
      this.end_x -= glyph.getMetrics().width;
      return this;
    },

    addModifier: function(modifier) {
      this.modifiers.push(modifier);
      modifier.addToStave(this, (this.glyphs.length === 0));
      return this;
    },

    addEndModifier: function(modifier) {
      this.modifiers.push(modifier);
      modifier.addToStaveEnd(this, (this.end_glyphs.length === 0));
      return this;
    },

    addKeySignature: function(keySpec) {
      this.addModifier(new Vex.Flow.KeySignature(keySpec));
      return this;
    },

    addClef: function(clef) {
      this.clef = clef;
      this.addModifier(new Vex.Flow.Clef(clef));
      return this;
    },

    addEndClef: function(clef) {
      this.addEndModifier(new Vex.Flow.Clef(clef));
      return this;
    },

    addTimeSignature: function(timeSpec, customPadding) {
      this.addModifier(new Vex.Flow.TimeSignature(timeSpec, customPadding));
      return this;
    },

    addEndTimeSignature: function(timeSpec, customPadding) {
      this.addEndModifier(new Vex.Flow.TimeSignature(timeSpec, customPadding));
    },

    addTrebleGlyph: function() {
      this.clef = "treble";
      this.addGlyph(new Vex.Flow.Glyph("v83", 40));
      return this;
    },

    /**
     * All drawing functions below need the context to be set.
     */
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw stave without canvas context.");

      var num_lines = this.options.num_lines;
      var width = this.width;
      var x = this.x;
      var y;
      var glyph;

      // Render lines
      for (var line=0; line < num_lines; line++) {
        y = this.getYForLine(line);

        this.context.save();
        this.context.setFillStyle(this.options.fill_style);
        this.context.setStrokeStyle(this.options.fill_style);
        if (this.options.line_config[line].visible) {
          this.context.fillRect(x, y, width, Vex.Flow.STAVE_LINE_THICKNESS);
        }
        this.context.restore();
      }

      // Render glyphs
      x = this.glyph_start_x;
      for (var i = 0; i < this.glyphs.length; ++i) {
        glyph = this.glyphs[i];
        if (!glyph.getContext()) {
          glyph.setContext(this.context);
        }
        glyph.renderToStave(x);
        x += glyph.getMetrics().width;
      }

      // Render end glyphs
      x = this.glyph_end_x;
      for (i = 0; i < this.end_glyphs.length; ++i) {
        glyph = this.end_glyphs[i];
        if (!glyph.getContext()) {
          glyph.setContext(this.context);
        }
        x -= glyph.getMetrics().width;
        glyph.renderToStave(x);
      }

      // Draw the modifiers (bar lines, coda, segno, repeat brackets, etc.)
      for (i = 0; i < this.modifiers.length; i++) {
        // Only draw modifier if it has a draw function
        if (typeof this.modifiers[i].draw == "function")
          this.modifiers[i].draw(this, this.getModifierXShift());
      }

      // Render measure numbers
      if (this.measure > 0) {
        this.context.save();
        this.context.setFont(this.font.family, this.font.size, this.font.weight);
        var text_width = this.context.measureText("" + this.measure).width;
        y = this.getYForTopText(0) + 3;
        this.context.fillText("" + this.measure, this.x - text_width / 2, y);
        this.context.restore();
      }

      return this;
    },

    // Draw Simple barlines for backward compatability
    // Do not delete - draws the beginning bar of the stave
    drawVertical: function(x, isDouble) {
      this.drawVerticalFixed(this.x + x, isDouble);
    },

    drawVerticalFixed: function(x, isDouble) {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw stave without canvas context.");

      var top_line = this.getYForLine(0);
      var bottom_line = this.getYForLine(this.options.num_lines - 1);
      if (isDouble)
        this.context.fillRect(x - 3, top_line, 1, bottom_line - top_line + 1);
      this.context.fillRect(x, top_line, 1, bottom_line - top_line + 1);
    },

    drawVerticalBar: function(x) {
      this.drawVerticalBarFixed(this.x + x, false);
    },

    drawVerticalBarFixed: function(x) {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw stave without canvas context.");

      var top_line = this.getYForLine(0);
      var bottom_line = this.getYForLine(this.options.num_lines - 1);
      this.context.fillRect(x, top_line, 1, bottom_line - top_line + 1);
    },

    /**
     * Get the current configuration for the Stave.
     * @return {Array} An array of configuration objects.
     */
    getConfigForLines: function() {
      return this.options.line_config;
    },

    /**
     * Configure properties of the lines in the Stave
     * @param line_number The index of the line to configure.
     * @param line_config An configuration object for the specified line.
     * @throws Vex.RERR "StaveConfigError" When the specified line number is out of
     *   range of the number of lines specified in the constructor.
     */
    setConfigForLine: function(line_number, line_config) {
      if (line_number >= this.options.num_lines || line_number < 0) {
        throw new Vex.RERR("StaveConfigError",
          "The line number must be within the range of the number of lines in the Stave.");
      }
      if (!line_config.hasOwnProperty('visible')) {
        throw new Vex.RERR("StaveConfigError",
          "The line configuration object is missing the 'visible' property.");
      }
      if (typeof(line_config.visible) !== 'boolean') {
        throw new Vex.RERR("StaveConfigError",
          "The line configuration objects 'visible' property must be true or false.");
      }

      this.options.line_config[line_number] = line_config;

      return this;
    },

    /**
     * Set the staff line configuration array for all of the lines at once.
     * @param lines_configuration An array of line configuration objects.  These objects
     *   are of the same format as the single one passed in to setLineConfiguration().
     *   The caller can set null for any line config entry if it is desired that the default be used
     * @throws Vex.RERR "StaveConfigError" When the lines_configuration array does not have
     *   exactly the same number of elements as the num_lines configuration object set in
     *   the constructor.
     */
    setConfigForLines: function(lines_configuration) {
      if (lines_configuration.length !== this.options.num_lines) {
        throw new Vex.RERR("StaveConfigError",
          "The length of the lines configuration array must match the number of lines in the Stave");
      }

      // Make sure the defaults are present in case an incomplete set of
      //  configuration options were supplied.
      for (var line_config in lines_configuration) {
        // Allow 'null' to be used if the caller just wants the default for a particular node.
        if (!lines_configuration[line_config]) {
          lines_configuration[line_config] = this.options.line_config[line_config];
        }
        Vex.Merge(this.options.line_config[line_config], lines_configuration[line_config]);
      }

      this.options.line_config = lines_configuration;

      return this;
    }
  };

  return Stave;
}());// Vex Flow Notation
// Mohit Muthanna <mohit@muthanna.com>
//
// Copyright Mohit Muthanna 2010
//
// Requires vex.js.

/** @constructor */
Vex.Flow.StaveConnector = (function() {
  function StaveConnector(top_stave, bottom_stave) {
    this.init(top_stave, bottom_stave);
  }

  // SINGLE_LEFT and SINGLE are the same value for compatibility
  // with older versions of vexflow which didn't have right sided
  // stave connectors
  StaveConnector.type = {
    SINGLE_RIGHT : 0,
    SINGLE_LEFT : 1,
    SINGLE: 1,
    DOUBLE: 2,
    BRACE: 3,
    BRACKET: 4,
    BOLD_DOUBLE_LEFT: 5,
    BOLD_DOUBLE_RIGHT: 6,
    THIN_DOUBLE: 7
  };

  var THICKNESS = Vex.Flow.STAVE_LINE_THICKNESS;

  StaveConnector.prototype = {
    init: function(top_stave, bottom_stave) {
      this.width = 3;
      this.top_stave = top_stave;
      this.bottom_stave = bottom_stave;
      this.type = StaveConnector.type.DOUBLE;
      this.x_shift = 0; // Mainly used to offset Bold Double Left to align with offset Repeat Begin bars
    },

    setContext: function(ctx) {
      this.ctx = ctx;
      return this;
    },

    setType: function(type) {
      if (type >= StaveConnector.type.SINGLE_RIGHT &&
          type <= StaveConnector.type.THIN_DOUBLE)
        this.type = type;
      return this;
    },

    setText: function(text, text_options) {
      this.text = text;
      this.text_options = {
        shift_x: 0,
        shift_y: 0
      };
      Vex.Merge(this.text_options, text_options);

      this.font = {
        family: "times",
        size: 16,
        weight: "normal"
      };
      return this;
    },

    setFont: function(font) {
      Vex.Merge(this.font, font);
    },

    setXShift: function(x_shift){
      if (typeof x_shift !== 'number') {
        throw Vex.RERR("InvalidType", "x_shift must be a Number");
      }

      this.x_shift = x_shift;
      return this;
    },

    draw: function() {
      if (!this.ctx) throw new Vex.RERR(
          "NoContext", "Can't draw without a context.");
      var topY = this.top_stave.getYForLine(0);
      var botY = this.bottom_stave.getYForLine(this.bottom_stave.getNumLines() - 1) +
        THICKNESS;
      var width = this.width;
      var topX = this.top_stave.getX();

      var isRightSidedConnector = (
        this.type === StaveConnector.type.SINGLE_RIGHT ||
        this.type === StaveConnector.type.BOLD_DOUBLE_RIGHT ||
        this.type === StaveConnector.type.THIN_DOUBLE
      );

      if (isRightSidedConnector){
        topX = this.top_stave.getX() + this.top_stave.width;
      }

      var attachment_height = botY - topY;
      switch (this.type) {
        case StaveConnector.type.SINGLE:
          width = 1;
          break;
        case StaveConnector.type.SINGLE_LEFT:
          width = 1;
          break;
        case StaveConnector.type.SINGLE_RIGHT:
          width = 1;
          break;
        case StaveConnector.type.DOUBLE:
          topX -= (this.width + 2);
          break;
        case StaveConnector.type.BRACE:
          width = 12;
          // May need additional code to draw brace
          var x1 = this.top_stave.getX() - 2;
          var y1 = topY;
          var x3 = x1;
          var y3 = botY;
          var x2 = x1 - width;
          var y2 = y1 + attachment_height/2.0;
          var cpx1 = x2 - (0.90 * width);
          var cpy1 = y1 + (0.2 * attachment_height);
          var cpx2 = x1 + (1.10 * width);
          var cpy2 = y2 - (0.135 * attachment_height);
          var cpx3 = cpx2;
          var cpy3 = y2 + (0.135 * attachment_height);
          var cpx4 = cpx1;
          var cpy4 = y3 - (0.2 * attachment_height);
          var cpx5 = x2 - width;
          var cpy5 = cpy4;
          var cpx6 = x1 + (0.40 * width);
          var cpy6 = y2 + (0.135 * attachment_height);
          var cpx7 = cpx6;
          var cpy7 = y2 - (0.135 * attachment_height);
          var cpx8 = cpx5;
          var cpy8 = cpy1;
          this.ctx.beginPath();
          this.ctx.moveTo(x1, y1);
          this.ctx.bezierCurveTo(cpx1, cpy1, cpx2, cpy2, x2, y2);
          this.ctx.bezierCurveTo(cpx3, cpy3, cpx4, cpy4, x3, y3);
          this.ctx.bezierCurveTo(cpx5, cpy5, cpx6, cpy6, x2, y2);
          this.ctx.bezierCurveTo(cpx7, cpy7, cpx8, cpy8, x1, y1);
          this.ctx.fill();
          this.ctx.stroke();
          break;
        case StaveConnector.type.BRACKET:
          topY -= 4;
          botY += 4;
          attachment_height = botY - topY;
          Vex.Flow.renderGlyph(this.ctx, topX - 5, topY - 3, 40, "v1b", true);
          Vex.Flow.renderGlyph(this.ctx, topX - 5, botY + 3, 40, "v10", true);
          topX -= (this.width + 2);
          break;
        case StaveConnector.type.BOLD_DOUBLE_LEFT:
          drawBoldDoubleLine(this.ctx, this.type, topX + this.x_shift, topY, botY);
          break;
        case StaveConnector.type.BOLD_DOUBLE_RIGHT:
          drawBoldDoubleLine(this.ctx, this.type, topX, topY, botY);
          break;
        case StaveConnector.type.THIN_DOUBLE:
          width = 1;
          break;
      }

      if (this.type !== StaveConnector.type.BRACE &&
        this.type !== StaveConnector.type.BOLD_DOUBLE_LEFT &&
        this.type !== StaveConnector.type.BOLD_DOUBLE_RIGHT) {
        this.ctx.fillRect(topX , topY, width, attachment_height);
      }

      // If the connector is a thin double barline, draw the paralell line
      if (this.type === StaveConnector.type.THIN_DOUBLE) {
        this.ctx.fillRect(topX - 3, topY, width, attachment_height);
      }

      // Add stave connector text
      if (this.text !== undefined) {
        this.ctx.save();
        this.ctx.lineWidth = 2;
        this.ctx.setFont(this.font.family, this.font.size, this.font.weight);
        var text_width = this.ctx.measureText("" + this.text).width;

        var x = this.top_stave.getX() - text_width - 24 + this.text_options.shift_x;
        var y = (this.top_stave.getYForLine(0) + this.bottom_stave.getBottomLineY()) / 2 +
          this.text_options.shift_y;

        this.ctx.fillText("" + this.text, x, y + 4);
        this.ctx.restore();
      }
    }
  };

  function drawBoldDoubleLine(ctx, type, topX, topY, botY){
    if (type !== StaveConnector.type.BOLD_DOUBLE_LEFT &&
        type !== StaveConnector.type.BOLD_DOUBLE_RIGHT) {
      throw Vex.RERR("InvalidConnector",
        "A REPEAT_BEGIN or REPEAT_END type must be provided.");
    }

    var x_shift = 3;
    var variableWidth = 3.5; // Width for avoiding anti-aliasing width issues
    var thickLineOffset = 2; // For aesthetics

    if (type === StaveConnector.type.BOLD_DOUBLE_RIGHT) {
      x_shift = -5; // Flips the side of the thin line
      variableWidth = 3;
    }

    // Thin line
    ctx.fillRect(topX + x_shift, topY, 1, botY - topY);
    // Thick line
    ctx.fillRect(topX - thickLineOffset, topY, variableWidth, botY - topY);
  }

  return StaveConnector;
}());// Vex Flow
// Mohit Muthanna <mohit@muthanna.com>
//
// Copyright Mohit Cheppudira 2010

/** @constructor */
Vex.Flow.TabStave = (function() {
  function TabStave(x, y, width, options) {
    if (arguments.length > 0) this.init(x, y, width, options);
  }

  Vex.Inherit(TabStave, Vex.Flow.Stave, {
    init: function(x, y, width, options) {
      var tab_options = {
        spacing_between_lines_px: 13,
        num_lines: 6,
        top_text_position: 1
      };

      Vex.Merge(tab_options, options);
      TabStave.superclass.init.call(this, x, y, width, tab_options);
    },

    getYForGlyphs: function() {
      return this.getYForLine(2.5);
    },

    addTabGlyph: function() {
      var glyphScale;
      var glyphOffset;

      switch(this.options.num_lines) {
        case 8:
          glyphScale = 55;
          glyphOffset = 14;
          break;
        case 7:
          glyphScale = 47;
          glyphOffset = 8;
          break;
        case 6:
          glyphScale = 40;
          glyphOffset = 1;
          break;
        case 5:
          glyphScale = 30;
          glyphOffset = -6;
          break;
        case 4:
          glyphScale = 23;
          glyphOffset = -12;
          break;
      }

      var tabGlyph = new Vex.Flow.Glyph("v2f", glyphScale);
      tabGlyph.y_shift = glyphOffset;
      this.addGlyph(tabGlyph);
      return this;
    }
  });

  return TabStave;
}());// Vex Flow
// Copyright Mohit Cheppudira <mohit@muthanna.com>
//
// A formatter for abstract tickable objects, such as notes, chords,
// tabs, etc.

/** @constructor */
Vex.Flow.TickContext = (function() {
  function TickContext() {
    this.init();
  }

  TickContext.prototype = {
    init: function() {
      this.currentTick = new Vex.Flow.Fraction(0, 1);
      this.maxTicks = new Vex.Flow.Fraction(0, 1);
      this.minTicks = null;
      this.width = 0;
      this.padding = 3;     // padding on each side (width += padding * 2)
      this.pixelsUsed = 0;
      this.x = 0;
      this.tickables = [];   // Notes, tabs, chords, lyrics.
      this.notePx = 0;       // width of widest note in this context
      this.extraLeftPx = 0;  // Extra left pixels for modifers & displace notes
      this.extraRightPx = 0; // Extra right pixels for modifers & displace notes

      // Ignore this tick context for formatting and justification
      this.ignore_ticks = true;
      this.preFormatted = false;
      this.postFormatted = false;
      this.context = null; // Rendering context
    },

    setContext: function(context) { this.context = context; return this; },
    getContext: function() { return this.context; },
    shouldIgnoreTicks: function() { return this.ignore_ticks; },
    getWidth: function() { return this.width + (this.padding * 2); },
    getX: function() { return this.x; },
    setX: function(x) { this.x = x; return this; },
    getPixelsUsed: function() { return this.pixelsUsed; },
    setPixelsUsed: function(pixelsUsed) { this.pixelsUsed = pixelsUsed; return this; },
    setPadding: function(padding) { this.padding = padding; return this; },
    getMaxTicks: function() { return this.maxTicks; },
    getMinTicks: function() { return this.minTicks; },
    getTickables: function() { return this.tickables; },

    // Get widths context, note and left/right modifiers for formatting
    getMetrics: function() {
      return { width: this.width, notePx: this.notePx,
               extraLeftPx: this.extraLeftPx, extraRightPx: this.extraRightPx };
    },

    getCurrentTick: function() { return this.currentTick; },
    setCurrentTick: function(tick) {
      this.currentTick = tick;
      this.preFormatted = false;
    },

    // Get left & right pixels used for modifiers
    getExtraPx: function() {
      var left_shift = 0;
      var right_shift = 0;
      var extraLeftPx = 0;
      var extraRightPx = 0;
      for (var i = 0; i < this.tickables.length; i++) {
        extraLeftPx = Math.max(this.tickables[i].extraLeftPx, extraLeftPx);
        extraRightPx = Math.max(this.tickables[i].extraRightPx, extraRightPx);
        var mContext = this.tickables[i].modifierContext;
        if (mContext && mContext != null) {
          left_shift = Math.max( left_shift, mContext.state.left_shift);
          right_shift = Math.max( right_shift, mContext.state.right_shift);
        }
      }
      return { left: left_shift, right: right_shift,
               extraLeft: extraLeftPx, extraRight: extraRightPx };
    },

    addTickable: function(tickable) {
      if (!tickable) {
        throw new Vex.RERR("BadArgument", "Invalid tickable added.");
      }

      if (!tickable.shouldIgnoreTicks()) {
        this.ignore_ticks = false;

        var ticks = tickable.getTicks();

        if (ticks.value() > this.maxTicks.value()) {
          this.maxTicks = ticks.clone();
        }

        if (this.minTicks == null) {
          this.minTicks = ticks.clone();
        } else if (ticks.value() < this.minTicks.value()) {
          this.minTicks = ticks.clone();
        }
      }

      tickable.setTickContext(this);
      this.tickables.push(tickable);
      this.preFormatted = false;
      return this;
    },

    preFormat: function() {
      if (this.preFormatted) return;

      for (var i = 0; i < this.tickables.length; ++i) {
        var tickable = this.tickables[i];
        tickable.preFormat();
        var metrics = tickable.getMetrics();

        // Maintain max extra pixels from all tickables in the context
        this.extraLeftPx = Math.max(this.extraLeftPx,
                                    metrics.extraLeftPx + metrics.modLeftPx);
        this.extraRightPx = Math.max(this.extraRightPx,
                                     metrics.extraRightPx + metrics.modRightPx);

        // Maintain the widest note for all tickables in the context
        this.notePx = Math.max(this.notePx, metrics.noteWidth);

        // Recalculate the tick context total width
        this.width = this.notePx +
                     this.extraLeftPx +
                     this.extraRightPx;
      }

      return this;
    },

    postFormat: function() {
      if (this.postFormatted) return this;
      this.postFormatted = true;
      return this;
    }
  };

  return TickContext;
}());
// Vex Flow
// Copyright Mohit Cheppudira <mohit@muthanna.com>
//
// The tickable interface. Tickables are things that sit on a score and
// have a duration, i.e., they occupy space in the musical rendering dimension.

/** @constructor */
Vex.Flow.Tickable = (function() {
  function Tickable() {
    this.init();
  }

  Tickable.prototype = {
    init: function() {
      this.intrinsicTicks = 0;
      this.tickMultiplier = new Vex.Flow.Fraction(1, 1);
      this.ticks = new Vex.Flow.Fraction(0, 1);
      this.width = 0;
      this.x_shift = 0; // Shift from tick context
      this.voice = null;
      this.tickContext = null;
      this.modifierContext = null;
      this.modifiers = [];
      this.preFormatted = false;
      this.postFormatted = false;
      this.tuplet = null;

      // This flag tells the formatter to ignore this tickable during
      // formatting and justification. It is set by tickables such as BarNote.
      this.ignore_ticks = false;
      this.context = null;
    },

    setContext: function(context) { this.context = context; },
    getBoundingBox: function() { return null; },
    getTicks: function() { return this.ticks; },
    shouldIgnoreTicks: function() { return this.ignore_ticks; },
    getWidth: function() { return this.width; },
    setXShift: function(x) { this.x_shift = x; },

    // Every tickable must be associated with a voice. This allows formatters
    // and preFormatter to associate them with the right modifierContexts.
    getVoice: function() {
      if (!this.voice) throw new Vex.RERR("NoVoice", "Tickable has no voice.");
      return this.voice;
    },
    setVoice: function(voice) { this.voice = voice; },

    getTuplet: function() { return this.tuplet; },
    setTuplet: function(tuplet) {
      // Detach from previous tuplet
      var noteCount, beatsOccupied;

      if (this.tuplet) {
        noteCount = this.tuplet.getNoteCount();
        beatsOccupied = this.tuplet.getBeatsOccupied();

        // Revert old multiplier
        this.applyTickMultiplier(noteCount, beatsOccupied);
      }

      // Attach to new tuplet
      if (tuplet) {
        noteCount = tuplet.getNoteCount();
        beatsOccupied = tuplet.getBeatsOccupied();

        this.applyTickMultiplier(beatsOccupied, noteCount);
      }

      this.tuplet = tuplet;

      return this;
    },

    /** optional, if tickable has modifiers **/
    addToModifierContext: function(mc) {
      this.modifierContext = mc;
      // Add modifiers to modifier context (if any)
      this.preFormatted = false;
    },

    /** optional, if tickable has modifiers **/
    addModifier: function(mod) {
      this.modifiers.push(mod);
      this.preFormatted = false;
      return this;
    },

    setTickContext: function(tc) {
      this.tickContext = tc;
      this.preFormatted = false;
    },

    preFormat: function() {
      if (this.preFormatted) return;

      this.width = 0;
      if (this.modifierContext) {
        this.modifierContext.preFormat();
        this.width += this.modifierContext.getWidth();
      }
    },

    postFormat: function() {
      if (this.postFormatted) return;
      this.postFormatted = true;
      return this;
    },

    getIntrinsicTicks: function() {
      return this.intrinsicTicks;
    },
    setIntrinsicTicks: function(intrinsicTicks) {
      this.intrinsicTicks = intrinsicTicks;
      this.ticks = this.tickMultiplier.clone().multiply(this.intrinsicTicks);
    },

    getTickMultiplier: function() {
      return this.tickMultiplier;
    },
    applyTickMultiplier: function(numerator, denominator) {
      this.tickMultiplier.multiply(numerator, denominator);
      this.ticks = this.tickMultiplier.clone().multiply(this.intrinsicTicks);
    }
  };

  return Tickable;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// This file implements an abstract interface for notes and chords that
// are rendered on a stave. Notes have some common properties: All of them
// have a value (e.g., pitch, fret, etc.) and a duration (quarter, half, etc.)
//
// Some notes have stems, heads, dots, etc. Most notational elements that
// surround a note are called *modifiers*, and every note has an associated
// array of them. All notes also have a rendering context and belong to a stave.

Vex.Flow.Note = (function() {
  // To create a new note you need to provide a `note_struct`, which consists
  // of the following fields:
  //
  // `type`: The note type (e.g., `r` for rest, `s` for slash notes, etc.)
  // `dots`: The number of dots, which affects the duration.
  // `duration`: The time length (e.g., `q` for quarter, `h` for half, `8` for eighth etc.)
  //
  // The range of values for these parameters are available in `src/tables.js`.
  function Note(note_struct) {
    if (arguments.length > 0) this.init(note_struct);
  }

  // ## Prototype Methods
  //
  // Every note is a tickable, i.e., it can be mutated by the `Formatter` class for
  // positioning and layout.
  Vex.Inherit(Note, Vex.Flow.Tickable, {
    // See constructor above for how to create a note.
    init: function(note_struct) {
      Note.superclass.init.call(this);

      if (!note_struct) {
        throw new Vex.RuntimeError("BadArguments",
            "Note must have valid initialization data to identify " +
            "duration and type.");
      }

      // Parse `note_struct` and get note properties.
      var initData = Vex.Flow.parseNoteData(note_struct);
      if (!initData) {
        throw new Vex.RuntimeError("BadArguments",
            "Invalid note initialization object: " + JSON.stringify(note_struct));
      }

      // Set note properties from parameters.
      this.duration = initData.duration;
      this.dots = initData.dots;
      this.noteType = initData.type;
      this.setIntrinsicTicks(initData.ticks);
      this.modifiers = [];

      // Get the glyph code for this note from the font.
      this.glyph = Vex.Flow.durationToGlyph(this.duration, this.noteType);

      if (this.positions &&
          (typeof(this.positions) != "object" || !this.positions.length)) {
        throw new Vex.RuntimeError(
          "BadArguments", "Note keys must be array type.");
      }

      // Note to play for audio players.
      this.playNote = null;

      // Positioning contexts used by the Formatter.
      this.tickContext = null;    // The current tick context.
      this.modifierContext = null;
      this.ignore_ticks = false;

      // Positioning variables
      this.width = 0;             // Width in pixels calculated after preFormat
      this.extraLeftPx = 0;       // Extra room on left for offset note head
      this.extraRightPx = 0;      // Extra room on right for offset note head
      this.x_shift = 0;           // X shift from tick context X
      this.left_modPx = 0;        // Max width of left modifiers
      this.right_modPx = 0;       // Max width of right modifiers
      this.voice = null;          // The voice that this note is in
      this.preFormatted = false;  // Is this note preFormatted?
      this.ys = [];               // list of y coordinates for each note
                                  // we need to hold on to these for ties and beams.

      // The render surface.
      this.context = null;
      this.stave = null;
      this.render_options = {
        annotation_spacing: 5,
        stave_padding: 12
      };
    },

    // Get and set the play note, which is arbitrary data that can be used by an
    // audio player.
    getPlayNote: function() { return this.playNote; },
    setPlayNote: function(note) { this.playNote = note; return this; },

    // Don't play notes by default, call them rests. This is also used by things like
    // beams and dots for positioning.
    isRest: function() { return false; },

    // TODO(0xfe): Why is this method here?
    addStroke: function(index, stroke) {
      stroke.setNote(this);
      stroke.setIndex(index);
      this.modifiers.push(stroke);
      this.setPreFormatted(false);
      return this;
    },

    // Get and set the target stave.
    getStave: function() { return this.stave; },
    setStave: function(stave) {
      this.stave = stave;
      this.setYs([stave.getYForLine(0)]); // Update Y values if the stave is changed.
      this.context = this.stave.context;
      return this;
    },

    // Set the rendering context for the note.
    setContext: function(context) { this.context = context; return this; },

    // Get and set spacing to the left and right of the notes.
    getExtraLeftPx: function() { return this.extraLeftPx; },
    getExtraRightPx: function() { return this.extraRightPx; },
    setExtraLeftPx: function(x) { this.extraLeftPx = x; return this; },
    setExtraRightPx: function(x) { this.extraRightPx = x; return this; },

    // Returns true if this note has no duration (e.g., bar notes, spacers, etc.)
    shouldIgnoreTicks: function() { return this.ignore_ticks; },

    // Get the stave line number for the note.
    getLineNumber: function() { return 0; },

    // Get the stave line number for rest.
    getLineForRest: function() { return 0; },

    // Get the glyph associated with this note.
    getGlyph: function() { return this.glyph; },

    // Set and get Y positions for this note. Each Y value is associated with
    // an individual pitch/key within the note/chord.
    setYs: function(ys) { this.ys = ys; return this; },
    getYs: function() {
      if (this.ys.length === 0) throw new Vex.RERR("NoYValues",
          "No Y-values calculated for this note.");
      return this.ys;
    },

    // Get the Y position of the space above the stave onto which text can
    // be rendered.
    getYForTopText: function(text_line) {
      if (!this.stave) throw new Vex.RERR("NoStave",
          "No stave attached to this note.");
      return this.stave.getYForTopText(text_line);
    },

    // Get a `BoundingBox` for this note.
    getBoundingBox: function() { return null; },

    // Returns the voice that this note belongs in.
    getVoice: function() {
      if (!this.voice) throw new Vex.RERR("NoVoice", "Note has no voice.");
      return this.voice;
    },

    // Attach this note to `voice`.
    setVoice: function(voice) {
      this.voice = voice;
      this.preFormatted = false;
      return this;
    },

    // Get and set the `TickContext` for this note.
    getTickContext: function() { return this.tickContext; },
    setTickContext: function(tc) {
      this.tickContext = tc;
      this.preFormatted = false;
      return this;
    },

    // Accessors for the note type.
    getDuration: function() { return this.duration; },
    isDotted: function() { return (this.dots > 0); },
    hasStem: function() { return false; },
    getDots: function() { return this.dots; },
    getNoteType: function() { return this.noteType; },
    setBeam: function() { return this; }, // ignore parameters

    // Attach this note to a modifier context.
    setModifierContext: function(mc) { this.modifierContext = mc; return this; },

    // Attach a modifier to this note.
    addModifier: function(modifier, index) {
      modifier.setNote(this);
      modifier.setIndex(index || 0);
      this.modifiers.push(modifier);
      this.setPreFormatted(false);
      return this;
    },

    // Get the coordinates for where modifiers begin.
    getModifierStartXY: function() {
      if (!this.preFormatted) throw new Vex.RERR("UnformattedNote",
          "Can't call GetModifierStartXY on an unformatted note");
      return {x: this.getAbsoluteX(), y: this.ys[0]};
    },

    // Get bounds and metrics for this note.
    //
    // Returns a struct with fields:
    // `width`: The total width of the note (including modifiers.)
    // `noteWidth`: The width of the note head only.
    // `left_shift`: The horizontal displacement of the note.
    // `modLeftPx`: Start `X` for left modifiers.
    // `modRightPx`: Start `X` for right modifiers.
    // `extraLeftPx`: Extra space on left of note.
    // `extraRightPx`: Extra space on right of note.
    getMetrics: function() {
      if (!this.preFormatted) throw new Vex.RERR("UnformattedNote",
          "Can't call getMetrics on an unformatted note.");
      var modLeftPx = 0;
      var modRightPx = 0;
      if (this.modifierContext != null) {
        modLeftPx = this.modifierContext.state.left_shift;
        modRightPx = this.modifierContext.state.right_shift;
      }

      var width = this.getWidth();
      return { width: width,
               noteWidth: width -
                          modLeftPx - modRightPx -  // used by accidentals and modifiers
                          this.extraLeftPx - this.extraRightPx,
               left_shift: this.x_shift, // TODO(0xfe): Make style consistent
               modLeftPx: modLeftPx,
               modRightPx: modRightPx,
               extraLeftPx: this.extraLeftPx,
               extraRightPx: this.extraRightPx };
    },

    // Get and set width of note. Used by the formatter for positioning.
    setWidth: function(width) { this.width = width; },
    getWidth: function() {
      if (!this.preFormatted) throw new Vex.RERR("UnformattedNote",
          "Can't call GetWidth on an unformatted note.");
      return this.width +
        (this.modifierContext ?  this.modifierContext.getWidth() : 0);
    },

    // Displace note by `x` pixels.
    setXShift: function(x) {
      this.x_shift = x;
      return this;
    },

    // Get `X` position of this tick context.
    getX: function() {
      if (!this.tickContext) throw new Vex.RERR("NoTickContext",
          "Note needs a TickContext assigned for an X-Value");
      return this.tickContext.getX() + this.x_shift;
    },

    // Get the absolute `X` position of this note relative to the stave.
    getAbsoluteX: function() {
      if (!this.tickContext) throw new Vex.RERR("NoTickContext",
          "Note needs a TickContext assigned for an X-Value");

      // {osition note to left edge of tick context.
      var x = this.tickContext.getX();
      if (this.stave) x += this.stave.getNoteStartX() + this.render_options.stave_padding;
      return x;
    },

    setPreFormatted: function(value) {
      this.preFormatted = value;

      // Maintain the width of left and right modifiers in pixels.
      if (this.preFormatted) {
        var extra = this.tickContext.getExtraPx();
        this.left_modPx = Math.max(this.left_modPx, extra.left);
        this.right_modPx = Math.max(this.right_modPx, extra.right);
      }
    }
  });

  return Note;
}());// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// This file implements `NoteHeads`. `NoteHeads` are typically not manipulated
// directly, but used internally in `StaveNote`.
//
// See `tests/notehead_tests.js` for usage examples.
Vex.Flow.NoteHead = (function() {
  var NoteHead = function(head_options) {
    if (arguments.length > 0) this.init(head_options);
  };

  // To enable logging for this class. Set `Vex.Flow.NoteHead.DEBUG` to `true`.
  function L() { if (NoteHead.DEBUG) Vex.L("Vex.Flow.NoteHead", arguments); }


  // Draw slashnote head manually. No glyph exists for this.
  //
  // Parameters:
  // * `ctx`: the Canvas context
  // * `duration`: the duration of the note. ex: "4"
  // * `x`: the x coordinate to draw at
  // * `y`: the y coordinate to draw at
  // * `stem_direction`: the direction of the stem
  function drawSlashNoteHead(ctx, duration, x, y, stem_direction) {
    var width = 15 + (Vex.Flow.STEM_WIDTH / 2);
    ctx.setLineWidth(Vex.Flow.STEM_WIDTH);

    var fill = false;
    if (duration != 1 &&
        duration != 2 &&
        duration != "h" &&
        duration != "w") {
      fill = true;
    }

    if (!fill) x -= (Vex.Flow.STEM_WIDTH / 2) * stem_direction;

    ctx.beginPath();
    ctx.moveTo(x, y + 11);
    ctx.lineTo(x, y + 1);
    ctx.lineTo(x + width, y - 10);
    ctx.lineTo(x + width, y);
    ctx.lineTo(x, y + 11);
    ctx.closePath();

    if (fill) {
       ctx.fill();
    } else {
      ctx.stroke();
    }
    ctx.setLineWidth(1);
  }

  // ## Prototype Methods
  Vex.Inherit(NoteHead, Vex.Flow.Note, {
    init: function(head_options) {
      NoteHead.superclass.init.call(this, head_options);
      this.index = head_options.index;
      this.x = head_options.x || 0;
      this.y = head_options.y || 0;
      this.note_type = head_options.note_type;
      this.duration = head_options.duration;
      this.displaced = head_options.displaced || false;
      this.stem_direction = head_options.stem_direction || Vex.Flow.StaveNote.STEM_UP;
      this.line = head_options.line;

      // Get glyph code based on duration and note type. This could be
      // regular notes, rests, or other custom codes.
      this.glyph = Vex.Flow.durationToGlyph(this.duration, this.note_type);
      if (!this.glyph) {
        throw new Vex.RuntimeError("BadArguments",
            "No glyph found for duration '" + this.duration +
            "' and type '" + this.note_type + "'");
      }

      this.glyph_code = this.glyph.code_head;
      this.x_shift = head_options.x_shift;
      if (head_options.custom_glyph_code) {
        this.custom_glyph = true;
        this.glyph_code = head_options.custom_glyph_code;
      }

      this.context = null;
      this.style = head_options.style;
      this.slashed = head_options.slashed;

      Vex.Merge(this.render_options, {
        glyph_font_scale: 35, // font size for note heads
        stroke_px: 3         // number of stroke px to the left and right of head
      });

      if (head_options.glyph_font_scale) {
        this.render_options.glyph_font_scale = head_options.glyph_font_scale;
      }

      this.setWidth(this.glyph.head_width);
    },

    // Get the `ModifierContext` category
    getCategory: function() { return "notehead"; },

    // Set the Cavnas context for drawing
    setContext: function(context) { this.context = context; return this;},

    // Get the width of the notehead
    getWidth: function() { return this.width; },

    // Determine if the notehead is displaced
    isDisplaced: function() { return this.displaced === true; },

    // Get/set the notehead's style
    // 
    // `style` is an `object` with the following properties: `shadowColor`,
    // `shadowBlur`, `fillStyle`, `strokeStyle`
    getStyle: function() { return this.style; },
    setStyle: function(style) { this.style = style; return this; },

    // Get the glyph data
    getGlyph: function(){ return this.glyph; },

    // Set the X coordinate
    setX: function(x){ this.x = x; return this; },

    // get/set the Y coordinate
    getY: function() { return this.y; },
    setY: function(y) { this.y = y;  return this; },

    // Get the stave line the notehead is placed on 
    getLine: function(){ return this.line; },

    // Get the canvas `x` coordinate position of the notehead.
    getAbsoluteX: function() {
      var getAbsoluteX = NoteHead.superclass.getAbsoluteX;

      // If the note has not been preformatted, then get the static x value
      // Otherwise, it's been formatted and we should use it's x value relative
      // to its tick context
      var x = !this.preFormatted ? this.x : getAbsoluteX.call(this);

      return x + (this.displaced ? this.width * this.stem_direction : 0);
    },

    // Get the `BoundingBox` for the `NoteHead`
    getBoundingBox: function() {
      if (!this.preFormatted) throw new Vex.RERR("UnformattedNote",
          "Can't call getBoundingBox on an unformatted note.");

      var spacing = this.stave.getSpacingBetweenLines();
      var half_spacing = spacing/2;
      var min_y = this.y - half_spacing;

      return new Vex.Flow.BoundingBox(this.getAbsoluteX(), min_y, this.width, spacing);
    },

    // Apply current style to Canvas `context`
    applyStyle: function(context) {
      var style = this.getStyle();
      if (style.shadowColor) context.setShadowColor(style.shadowColor);
      if (style.shadowBlur) context.setShadowBlur(style.shadowBlur);
      if (style.fillStyle) context.setFillStyle(style.fillStyle);
      if (style.strokeStyle) context.setStrokeStyle(style.strokeStyle);
      return this;
    },

    // Set notehead to a provided `stave`
    setStave: function(stave){
      var line = this.getLine();

      this.stave = stave;
      this.setY(stave.getYForNote(line));
      this.context = this.stave.context;
      return this;
    },

    // Pre-render formatting
    preFormat: function() {
      if (this.preFormatted) return this;

      var glyph = this.getGlyph();
      var width = glyph.head_width + this.extraLeftPx + this.extraRightPx;

      this.setWidth(width);
      this.setPreFormatted(true);
      return this;
    },

    // Draw the notehead
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");

      var ctx = this.context;
      var head_x = this.getAbsoluteX();
      var y = this.y;

      L("Drawing note head '", this.note_type, this.duration, "' at", head_x, y);

      // Begin and end positions for head.
      var stem_direction = this.stem_direction;
      var glyph_font_scale = this.render_options.glyph_font_scale;

      var line = this.line;

      // If note above/below the staff, draw the small staff
      if (line <= 0 || line >= 6) {
        var line_y = y;
        var floor = Math.floor(line);
        if (line < 0 && floor - line == -0.5)
          line_y -= 5;
        else if (line > 6 &&  floor - line == -0.5)
          line_y += 5;
        ctx.fillRect(
          head_x - this.render_options.stroke_px, line_y,
          (this.getGlyph().head_width) +
          (this.render_options.stroke_px * 2), 1);
      }

      if (this.note_type == "s") {
        drawSlashNoteHead(ctx, this.duration,
          head_x, y, stem_direction);
      } else {
        if (this.style) {
          ctx.save();
          this.applyStyle(ctx);
          Vex.Flow.renderGlyph(ctx, head_x, y, glyph_font_scale, this.glyph_code);
          ctx.restore();
        } else {
          Vex.Flow.renderGlyph(ctx, head_x, y, glyph_font_scale, this.glyph_code);
        }
      }
    }
  });

  return NoteHead;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
// 
// This file implements the `Stem` object. Generally this object is handled 
// by its parent `StemmableNote`.
// 
Vex.Flow.Stem = (function() {
  var Stem = function(options) {
    if (arguments.length > 0) this.init(options);
  };

  // To enable logging for this class. Set `Vex.Flow.Stem.DEBUG` to `true`.
  function L() { if (Stem.DEBUG) Vex.L("Vex.Flow.Stem", arguments); }

  // Stem directions
  Stem.UP = 1;
  Stem.DOWN = -1;

  // Theme
  Stem.WIDTH = Vex.Flow.STEM_WIDTH;
  Stem.HEIGHT = Vex.Flow.STEM_HEIGHT;

  // ## Prototype Methods
  Stem.prototype = {
    init: function(options) {
      // Default notehead x bounds
      this.x_begin = options.x_begin || 0;
      this.x_end = options.x_end || 0;

      // Y bounds for top/bottom most notehead
      this.y_top = options.y_top || 0;
      this.y_bottom = options.y_bottom || 0;

      // Stem base extension
      this.y_extend = options.y_extend || 0;
      // Stem top extension
      this.stem_extension = options.stem_extension || 0;

      // Direction of the stem
      this.stem_direction = options.stem_direction || 0;

      // Flag to override all draw calls
      this.hide = false;
    },

    // Set the x bounds for the default notehead
    setNoteHeadXBounds: function(x_begin, x_end) {
      this.x_begin = x_begin;
      this.x_end = x_end;
      return this;
    },

    // Set the direction of the stem in relation to the noteheads
    setDirection: function(direction){ this.stem_direction = direction; },

    // Set the extension for the stem, generally for flags or beams
    setExtension: function(ext) { this.stem_extension = ext; },

    // The the y bounds for the top and bottom noteheads
    setYBounds: function(y_top, y_bottom) {
      this.y_top = y_top;
      this.y_bottom = y_bottom;
    },

    // The category of the object
    getCategory: function() { return "stem"; },

    // Set the canvas context to render on
    setContext: function(context) { this.context = context; return this;},

    // Gets the entire height for the stem
    getHeight: function() {
      return ((this.y_bottom - this.y_top) * this.stem_direction) +
             ((Stem.HEIGHT + this.stem_extension) * this.stem_direction);
    },

    getBoundingBox: function() {
      throw new Vex.RERR("NotImplemented", "getBoundingBox() not implemented.");
    },

    // Get the y coordinates for the very base of the stem to the top of
    // the extension
    getExtents: function() {
      var ys = [this.y_top, this.y_bottom];

      var top_pixel = this.y_top;
      var base_pixel = this.y_bottom;
      var stem_height = Stem.HEIGHT + this.stem_extension;

      for (var i = 0; i < ys.length; ++i) {
        var stem_top = ys[i] + (stem_height * -this.stem_direction);

        if (this.stem_direction == Stem.DOWN) {
          top_pixel = (top_pixel > stem_top) ? top_pixel : stem_top;
          base_pixel = (base_pixel < ys[i]) ? base_pixel : ys[i];
        } else {
          top_pixel = (top_pixel < stem_top) ? top_pixel : stem_top;
          base_pixel = (base_pixel > ys[i]) ? base_pixel : ys[i];
        }
      }
      
      return { topY: top_pixel, baseY: base_pixel };
    },

    // Render the stem onto the canvas
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");

      if (this.hide) return;

      var ctx = this.context;
      var stem_x, stem_y;
      var stem_direction = this.stem_direction;

      if (stem_direction == Stem.DOWN) {
        // Down stems are rendered to the left of the head.
        stem_x = this.x_begin + (Stem.WIDTH / 2);
        stem_y = this.y_top + 2;
      } else {
        // Up stems are rendered to the right of the head.
        stem_x = this.x_end + (Stem.WIDTH / 2);
        stem_y = this.y_bottom - 2;
      }

      stem_y += this.y_extend * stem_direction;

      L("Rendering stem - ", "Top Y: ", this.y_top, "Bottom Y: ", this.y_bottom);

      // Draw the stem
      ctx.beginPath();
      ctx.setLineWidth(Stem.WIDTH);
      ctx.moveTo(stem_x, stem_y);
      ctx.lineTo(stem_x, stem_y - this.getHeight());
      ctx.stroke();
      ctx.setLineWidth(1);
    }
  };

  return Stem;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// `StemmableNote` is an abstract interface for notes with optional stems. 
// Examples of stemmable notes are `StaveNote` and `TabNote`
Vex.Flow.StemmableNote = (function(){
  var StemmableNote = function(note_struct) {
    if (arguments.length > 0) this.init(note_struct);
  };

  // To enable logging for this class. Set `Vex.Flow.StemmableNote.DEBUG` to `true`.
  function L() { if (StemmableNote.DEBUG) Vex.L("Vex.Flow.StemmableNote", arguments); }

  var Stem = Vex.Flow.Stem;

  Vex.Inherit(StemmableNote, Vex.Flow.Note, {
    init: function(note_struct){
      StemmableNote.superclass.init.call(this, note_struct);

      this.stem = null;
      this.stem_extension_override = null;
      this.beam = null;
      
    },

    // Get and set the note's `Stem`
    getStem: function() {return this.stem; },
    setStem: function(stem) { this.stem = stem; return this; },

    // Builds and sets a new stem
    buildStem: function() {
      var stem = new Stem();
      this.setStem(stem);
      return this;
    },

    // Get the full length of stem
    getStemLength: function() {
      return Stem.HEIGHT + this.getStemExtension();
    },

    // Get the number of beams for this duration
    getBeamCount: function(){
      var glyph = this.getGlyph();

      if (glyph) {
        return glyph.beam_count;
      } else {
        return 0;
      }
    },

    // Get the minimum length of stem
    getStemMinumumLength: function() {
      var length = this.duration == "w" || this.duration == "1" ? 0 : 20;
      // if note is flagged, cannot shorten beam
      switch (this.duration) {
       case "8":
         if (this.beam == null) length = 35;
         break;
       case "16":
         if (this.beam == null)
           length = 35;
         else
           length = 25;
         break;
       case "32":
         if (this.beam == null)
           length = 45;
         else
           length = 35;
         break;
       case "64":
         if (this.beam == null)
           length = 50;
         else
           length = 40;
         break;
       case "128":
         if (this.beam == null)
           length = 55;
         else
           length = 45;
      }
      return length;
    },

    // Get/set the direction of the stem
    getStemDirection: function() { return this.stem_direction; },
    setStemDirection: function(direction) {
      if (!direction) direction = Stem.UP;
      if (direction != Stem.UP &&
          direction != Stem.DOWN) {
        throw new Vex.RERR("BadArgument", "Invalid stem direction: " +
            direction);
      }

      this.stem_direction = direction;
      if (this.stem) {
        this.stem.setDirection(direction);
        this.stem.setExtension(this.getStemExtension());
      }

      this.beam = null;
      if (this.preFormatted) {
        this.preFormat();
      }
      return this;
    },

    // Get the `x` coordinate of the stem
    getStemX: function() {
      var x_begin = this.getAbsoluteX() + this.x_shift;
      var x_end = this.getAbsoluteX() + this.x_shift + this.glyph.head_width;

      var stem_x = this.stem_direction == Stem.DOWN ?
        x_begin : x_end;

      stem_x -= ((Stem.WIDTH / 2) * this.stem_direction);

      return stem_x;
    },

    // Get the `x` coordinate for the center of the glyph.
    // Used for `TabNote` stems and stemlets over rests
    getCenterGlyphX: function(){
      return this.getAbsoluteX() + this.x_shift + (this.glyph.head_width / 2);
    },

    // Get the stem extension for the current duration
    getStemExtension: function(){
      var glyph = this.getGlyph();

      if (this.stem_extension_override != null) {
        return this.stem_extension_override;
      }

      if (glyph) {
        return this.getStemDirection() === 1 ? glyph.stem_up_extension :
          glyph.stem_down_extension;
      }

      return 0;
    },

    // Set the stem length to a specific. Will override the default length.
    setStemLength: function(height) {
      this.stem_extension_override = (height - Stem.HEIGHT);
      return this;
    },

    // Get the top and bottom `y` values of the stem.
    getStemExtents: function() {
      if (!this.ys || this.ys.length === 0) throw new Vex.RERR("NoYValues",
          "Can't get top stem Y when note has no Y values.");

      var top_pixel = this.ys[0];
      var base_pixel = this.ys[0];
      var stem_height = Stem.HEIGHT + this.getStemExtension();

      for (var i = 0; i < this.ys.length; ++i) {
        var stem_top = this.ys[i] + (stem_height * -this.stem_direction);

        if (this.stem_direction == Stem.DOWN) {
          top_pixel = (top_pixel > stem_top) ? top_pixel : stem_top;
          base_pixel = (base_pixel < this.ys[i]) ? base_pixel : this.ys[i];
        } else {
          top_pixel = (top_pixel < stem_top) ? top_pixel : stem_top;
          base_pixel = (base_pixel > this.ys[i]) ? base_pixel : this.ys[i];
        }

        if(this.noteType == "s" || this.noteType == 'x') {
          top_pixel -= this.stem_direction * 7;
          base_pixel -= this.stem_direction * 7;
        }
      }

      L("Stem extents: ", top_pixel, base_pixel);
      return { topY: top_pixel, baseY: base_pixel };
    },

    // Sets the current note's beam
    setBeam: function(beam) { this.beam = beam; return this; },

    // Get the `y` value for the top/bottom modifiers at a specific `text_line`
    getYForTopText: function(text_line) {
      var extents = this.getStemExtents();
      if (this.hasStem()) {
        return Vex.Min(this.stave.getYForTopText(text_line),
            extents.topY - (this.render_options.annotation_spacing * (text_line + 1)));
      } else {
        return this.stave.getYForTopText(text_line);
      }
    },
    getYForBottomText: function(text_line) {
      var extents = this.getStemExtents();
      if (this.hasStem()) {
        return Vex.Max(this.stave.getYForTopText(text_line),
          extents.baseY + (this.render_options.annotation_spacing * (text_line)));
      } else {
        return this.stave.getYForBottomText(text_line);
      }
    },

    // Post format the note
    postFormat: function() {
      if (this.beam) {
        this.beam.postFormat();
      }
      this.postFormatted = true;
      return this;
    },

    // Render the stem onto the canvas
    drawStem: function(stem_struct){
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");
      
      this.setStem(new Stem(stem_struct));
      this.stem.setContext(this.context).draw();
    }
  });

  return StemmableNote;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// This file implements notes for standard notation. This consists of one or 
// more `NoteHeads`, an optional stem, and an optional flag.
//
// *Throughout these comments, a "note" refers to the entire `StaveNote`,
// and a "key" refers to a specific pitch/notehead within a note.*
//
// See `tests/stavenote_tests.js` for usage examples.
Vex.Flow.StaveNote = (function() {
  var StaveNote = function(note_struct) {
    if (arguments.length > 0) this.init(note_struct);
  };

  // To enable logging for this class. Set `Vex.Flow.StaveNote.DEBUG` to `true`.
  function L() { if (StaveNote.DEBUG) Vex.L("Vex.Flow.StaveNote", arguments); }

  var Stem = Vex.Flow.Stem;
  var NoteHead = Vex.Flow.NoteHead;

  // Stem directions
  StaveNote.STEM_UP = Stem.UP;
  StaveNote.STEM_DOWN = Stem.DOWN;

  // ## Prototype Methods
  //
  Vex.Inherit(StaveNote, Vex.Flow.StemmableNote, {
    init: function(note_struct) {
      StaveNote.superclass.init.call(this, note_struct);

      this.keys = note_struct.keys;
      this.clef = note_struct.clef;
      this.beam = null;

      // Pull note rendering properties
      this.glyph = Vex.Flow.durationToGlyph(this.duration, this.noteType);
      if (!this.glyph) {
        throw new Vex.RuntimeError("BadArguments",
            "Invalid note initialization data (No glyph found): " +
            JSON.stringify(note_struct));
      }

      // if true, displace note to right
      this.displaced = false;
      this.dot_shiftY = 0;
      // per-pitch properties
      this.keyProps = [];
      // for displaced ledger lines
      this.use_default_head_x = false;

      // Drawing
      this.note_heads = [];
      this.modifiers = [];

      Vex.Merge(this.render_options, {
        // font size for note heads and rests
        glyph_font_scale: 35,
        // number of stroke px to the left and right of head
        stroke_px: 3
      });

      this.calculateKeyProps();

      this.buildStem();

      // Set the stem direction
      if (note_struct.auto_stem) {
        this.autoStem();
      } else {
        this.setStemDirection(note_struct.stem_direction);
      }

      this.buildNoteHeads();

      // Calculate left/right padding
      this.calcExtraPx();
    },

    // Builds a `Stem` for the note
    buildStem: function() {
      var glyph = this.getGlyph();

      var y_extend = 0;
      if (glyph.code_head == "v95" || glyph.code_head == "v3e") {
         y_extend = -4;
      }

      var stem = new Stem({
        y_extend: y_extend
      });

      if (this.isRest()) {
        stem.hide = true;
      }

      this.setStem(stem);
    },

    // Builds a `NoteHead` for each key in the note
    buildNoteHeads: function() {
      var stem_direction = this.getStemDirection();

      var keys = this.getKeys();

      var last_line = null;
      var line_diff = null;
      var displaced = false;

      // Draw notes from bottom to top.
      var start_i = 0;
      var end_i = keys.length;
      var step_i = 1;

      // For down-stem notes, we draw from top to bottom.
      if (stem_direction === Stem.DOWN) {
        start_i = keys.length - 1;
        end_i = -1;
        step_i = -1;
      }

      for (var i = start_i; i != end_i; i += step_i) {
        var note_props = this.keyProps[i];

        var line = note_props.line;

        // Keep track of last line with a note head, so that consecutive heads
        // are correctly displaced.
        if (last_line === null) {
          last_line = line;
        } else {
          line_diff = Math.abs(last_line - line);
          if (line_diff === 0 || line_diff === 0.5) {
            displaced = !displaced;
          } else {
            displaced = false;
            this.use_default_head_x = true;
          }
        }
        last_line = line;

        var note_head = new NoteHead({
          duration: this.duration,
          note_type: this.noteType,
          displaced: displaced,
          stem_direction: stem_direction,
          custom_glyph_code: note_props.code,
          glyph_font_scale: this.render_options.glyph_font_scale,
          x_shift: note_props.shift_right,
          line: note_props.line
        });

        this.note_heads[i] = note_head;
      }
    },

    // Automatically sets the stem direction based on the keys in the note
    autoStem: function() {
      var auto_stem_direction;

      // Figure out optimal stem direction based on given notes
      this.min_line = this.keyProps[0].line;
      this.max_line = this.keyProps[this.keyProps.length - 1].line;
      var decider = (this.min_line + this.max_line) / 2;

      if (decider < 3) {
        auto_stem_direction = 1;
      } else {
        auto_stem_direction = -1;
      }

      this.setStemDirection(auto_stem_direction);
    },

    // Calculates and stores the properties for each key in the note
    calculateKeyProps: function() {
      var last_line = null;
      for (var i = 0; i < this.keys.length; ++i) {
        var key = this.keys[i];

        // All rests use the same position on the line.
        // if (this.glyph.rest) key = this.glyph.position;
        if (this.glyph.rest) this.glyph.position = key;
        var props = Vex.Flow.keyProperties(key, this.clef);
        if (!props) {
          throw new Vex.RuntimeError("BadArguments",
              "Invalid key for note properties: " + key);
        }

        // Calculate displacement of this note
        var line = props.line;
        if (last_line === null) {
          last_line = line;
        } else {
          if (Math.abs(last_line - line) == 0.5) {
            this.displaced = true;
            props.displaced = true;

            // Have to mark the previous note as
            // displaced as well, for modifier placement
            if (this.keyProps.length > 0) {
                this.keyProps[i-1].displaced = true;
            }
          }
        }

        last_line = line;
        this.keyProps.push(props);
      }

      // Sort the notes from lowest line to highest line
      this.keyProps.sort(function(a, b) { return a.line - b.line; });
    },

    // Get modifier category for `ModifierContext`
    getCategory: function() { return "stavenotes"; },

    // Get the `BoundingBox` for the entire note
    getBoundingBox: function() {
      if (!this.preFormatted) throw new Vex.RERR("UnformattedNote",
          "Can't call getBoundingBox on an unformatted note.");

      var metrics = this.getMetrics();

      var w = metrics.width;
      var x = this.getAbsoluteX() - metrics.modLeftPx - metrics.extraLeftPx;

      var min_y = 0;
      var max_y = 0;
      var half_line_spacing = this.getStave().getSpacingBetweenLines() / 2;
      var line_spacing = half_line_spacing * 2;

      if (this.isRest()) {
        var y = this.ys[0];
        if (this.duration == "w" || this.duration == "h" ||
            this.duration == "1" || this.duration == "2") {
          min_y = y - half_line_spacing;
          max_y = y + half_line_spacing;
        } else {
          min_y = y - (this.glyph.line_above * line_spacing);
          max_y = y + (this.glyph.line_below * line_spacing);
        }
      } else if (this.glyph.stem) {
        var ys = this.getStemExtents();
        ys.baseY += half_line_spacing * this.stem_direction;
        min_y = Vex.Min(ys.topY, ys.baseY);
        max_y = Vex.Max(ys.topY, ys.baseY);
      } else {
        min_y = null;
        max_y = null;

        for (var i=0; i < this.ys.length; ++i) {
          var yy = this.ys[i];
          if (i === 0) {
            min_y = yy;
            max_y = yy;
          } else {
            min_y = Vex.Min(yy, min_y);
            max_y = Vex.Max(yy, max_y);
          }
          min_y -= half_line_spacing;
          max_y += half_line_spacing;
        }
      }

      return new Vex.Flow.BoundingBox(x, min_y, w, max_y - min_y);
    },

    // Gets the line number of the top or bottom note in the chord.
    // If `is_top_note` is `true` then get the top note
    getLineNumber: function(is_top_note) {
      if(!this.keyProps.length) throw new Vex.RERR("NoKeyProps",
          "Can't get bottom note line, because note is not initialized properly.");
      var result_line = this.keyProps[0].line;

      // No precondition assumed for sortedness of keyProps array
      for(var i=0; i<this.keyProps.length; i++){
        var this_line = this.keyProps[i].line;
        if(is_top_note)
          if(this_line > result_line)
                result_line = this_line;
        else
          if(this_line < result_line)
            result_line = this_line;
      }

      return result_line;
    },

    // Determine if current note is a rest
    isRest: function() { return this.glyph.rest; },

    // Determine if the current note is a chord
    isChord: function() { return !this.isRest() && this.keys.length > 1; },

    // Determine if the `StaveNote` has a stem
    hasStem: function() { return this.glyph.stem; },

    // Get the `y` coordinate for text placed on the top/bottom of a
    // note at a desired `text_line`
    getYForTopText: function(text_line) {
      var extents = this.getStemExtents();
      return Vex.Min(this.stave.getYForTopText(text_line),
          extents.topY - (this.render_options.annotation_spacing * (text_line + 1)));
    },
    getYForBottomText: function(text_line) {
      var extents = this.getStemExtents();
      return Vex.Max(this.stave.getYForTopText(text_line),
          extents.baseY + (this.render_options.annotation_spacing * (text_line)));
    },

    // Sets the current note to the provided `stave`. This applies
    // `y` values to the `NoteHeads`.
    setStave: function(stave) {
      var superclass = Vex.Flow.StaveNote.superclass;
      superclass.setStave.call(this, stave);

      var ys = this.note_heads.map(function(note_head) {
        note_head.setStave(stave);
        return note_head.getY();
      });

      this.setYs(ys);

      var bounds = this.getNoteHeadBounds();
      this.stem.setYBounds(bounds.y_top, bounds.y_bottom);

      return this;
    },

    // Get the pitches in the note
    getKeys: function() { return this.keys; },

    // Get the properties for all the keys in the note
    getKeyProps: function() {
      return this.keyProps;
    },

    // Check if note is shifted to the right
    isDisplaced: function() {
      return this.displaced;
    },

    // Sets whether shift note to the right. `displaced` is a `boolean`
    setNoteDisplaced: function(displaced) {
      this.displaced = displaced;
      return this;
    },

    // Get the starting `x` coordinate for a `StaveTie`
    getTieRightX: function() {
      var tieStartX = this.getAbsoluteX();
      tieStartX += this.glyph.head_width + this.x_shift + this.extraRightPx;
      if (this.modifierContext) tieStartX += this.modifierContext.getExtraRightPx();
      return tieStartX;
    },

    // Get the ending `x` coordinate for a `StaveTie`
    getTieLeftX: function() {
      var tieEndX = this.getAbsoluteX();
      tieEndX += this.x_shift - this.extraLeftPx;
      return tieEndX;
    },

    // Get the stave line on which to place a rest
    getLineForRest: function() {
      var rest_line = this.keyProps[0].line;
      if (this.keyProps.length > 1) {
        var last_line  = this.keyProps[this.keyProps.length - 1].line;
        var top = Vex.Max(rest_line, last_line);
        var bot = Vex.Min(rest_line, last_line);
        rest_line = Vex.MidLine(top, bot);
      }

      return rest_line;
    },

    // Get the default `x` and `y` coordinates for the provided `position`
    // and key `index`
    getModifierStartXY: function(position, index) {
      if (!this.preFormatted) throw new Vex.RERR("UnformattedNote",
          "Can't call GetModifierStartXY on an unformatted note");

      if (this.ys.length === 0) throw new Vex.RERR("NoYValues",
          "No Y-Values calculated for this note.");

      var x = 0;
      if (position == Vex.Flow.Modifier.Position.LEFT) {
        // extra_left_px
        x = -1 * 2;
      } else if (position == Vex.Flow.Modifier.Position.RIGHT) {
        // extra_right_px
        x = this.glyph.head_width + this.x_shift + 2;
      } else if (position == Vex.Flow.Modifier.Position.BELOW ||
                 position == Vex.Flow.Modifier.Position.ABOVE) {
        x = this.glyph.head_width / 2;
      }

      return { x: this.getAbsoluteX() + x, y: this.ys[index] };
    },

    // Sets the notehead at `index` to the provided coloring `style`.
    //
    // `style` is an `object` with the following properties: `shadowColor`,
    // `shadowBlur`, `fillStyle`, `strokeStyle`
    setKeyStyle: function(index, style) {
      this.note_heads[index].setStyle(style);
      return this;
    },

    // Add self to modifier context. `mContext` is the `ModifierContext`
    // to be added to.
    addToModifierContext: function(mContext) {
      this.setModifierContext(mContext);
      for (var i = 0; i < this.modifiers.length; ++i) {
        this.modifierContext.addModifier(this.modifiers[i]);
      }
      this.modifierContext.addModifier(this);
      this.setPreFormatted(false);
      return this;
    },

    // Generic function to add modifiers to a note
    // 
    // Parameters:
    // * `index`: The index of the key that we're modifying
    // * `modifier`: The modifier to add
    addModifier: function(index, modifier) {
      modifier.setNote(this);
      modifier.setIndex(index);
      this.modifiers.push(modifier);
      this.setPreFormatted(false);
      return this;
    },

    // Helper function to add an accidental to a key
    addAccidental: function(index, accidental) {
      return this.addModifier(index, accidental);
    },

    // Helper function to add an articulation to a key
    addArticulation: function(index, articulation) {
      return this.addModifier(index, articulation);
    },

    // Helper function to add an annotation to a key
    addAnnotation: function(index, annotation) {
      return this.addModifier(index, annotation);
    },

    // Helper function to add a dot on a specific key
    addDot: function(index) {
      var dot = new Vex.Flow.Dot();
      dot.setDotShiftY(this.glyph.dot_shiftY);
      this.dots++;
      return this.addModifier(index, dot);
    },

    // Convenience method to add dot to all keys in note
    addDotToAll: function() {
      for (var i = 0; i < this.keys.length; ++i)
        this.addDot(i);
      return this;
    },

    // Get all accidentals in the `ModifierContext`
    getAccidentals: function() {
      return this.modifierContext.getModifiers("accidentals");
    },

    // Get all dots in the `ModifierContext`
    getDots: function() {
      return this.modifierContext.getModifiers("dots");
    },

    // Get the width of the note if it is displaced. Used for `Voice`
    // formatting
    getVoiceShiftWidth: function() {
      // TODO: may need to accomodate for dot here.
      return this.glyph.head_width * (this.displaced ? 2 : 1);
    },

    // Calculates and sets the extra pixels to the left or right
    // if the note is displaced
    calcExtraPx: function() {
      this.setExtraLeftPx((this.displaced && this.stem_direction == -1) ?
          this.glyph.head_width : 0);
      this.setExtraRightPx((this.displaced && this.stem_direction == 1) ?
          this.glyph.head_width : 0);
    },

    // Pre-render formatting
    preFormat: function() {
      if (this.preFormatted) return;
      if (this.modifierContext) this.modifierContext.preFormat();

      var width = this.glyph.head_width + this.extraLeftPx + this.extraRightPx;

      // For upward flagged notes, the width of the flag needs to be added
      if (this.glyph.flag && this.beam === null && this.stem_direction == 1) {
        width += this.glyph.head_width;
      }

      this.setWidth(width);
      this.setPreFormatted(true);
    },

    // Gets the staff line and y value for the highest and lowest noteheads
    getNoteHeadBounds: function() {
      // Top and bottom Y values for stem.
      var y_top = null;
      var y_bottom = null;

      var highest_line = this.stave.getNumLines();
      var lowest_line = 1;

      this.note_heads.forEach(function(note_head) {
        var line = note_head.getLine();
        var y = note_head.getY();

        if (y_top === null || y < y_top)  {
          y_top = y;
        }

        if (y_bottom === null || y > y_bottom) {
          y_bottom = y;
        }

        highest_line = line > highest_line ? line : highest_line;
        lowest_line = line < lowest_line ? line : lowest_line;

      }, this);

      return {
        y_top: y_top,
        y_bottom: y_bottom,
        highest_line: highest_line,
        lowest_line: lowest_line
      };
    },

    // Get the starting `x` coordinate for the noteheads
    getNoteHeadBeginX: function(){
      return this.getAbsoluteX() + this.x_shift;
    },

    // Get the ending `x` coordinate for the noteheads
    getNoteHeadEndX: function(){
      var x_begin = this.getNoteHeadBeginX();
      return x_begin + this.glyph.head_width - (Vex.Flow.STEM_WIDTH / 2);
    },

    // Draw the ledger lines between the stave and the highest/lowest keys
    drawLedgerLines: function(){
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");
      var ctx = this.context;

      var bounds = this.getNoteHeadBounds();
      var highest_line = bounds.highest_line;
      var lowest_line = bounds.lowest_line;
      var head_x = this.note_heads[0].getAbsoluteX();

      var that = this;
      function stroke(y) {
        if (that.use_default_head_x === true)  {
          head_x = that.getAbsoluteX() + that.x_shift;
        }
        var x = head_x - that.render_options.stroke_px;
        var length = ((head_x + that.glyph.head_width) - head_x) +
          (that.render_options.stroke_px * 2);

        ctx.fillRect(x, y, length, 1);
      }

      var line; // iterator
      for (line = 6; line <= highest_line; ++line) {
        stroke(this.stave.getYForNote(line));
      }

      for (line = 0; line >= lowest_line; --line) {
        stroke(this.stave.getYForNote(line));
      }
    },

    // Draw all key modifiers
    drawModifiers: function(){
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");
      var ctx = this.context;
      for (var i = 0; i < this.modifiers.length; i++) {
        var mod = this.modifiers[i];
        var note_head = this.note_heads[mod.getIndex()];
        var key_style = note_head.getStyle();
        if(key_style) {
            ctx.save();
            note_head.applyKeyStyle(ctx);
        }
        mod.setContext(ctx);
        mod.draw();
        if(key_style) {
            ctx.restore();
        }
      }
    },

    // Draw the flag for the note
    drawFlag: function(){
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");
      var ctx = this.context;
      var glyph = this.getGlyph();
      var render_flag = this.beam === null;
      var bounds = this.getNoteHeadBounds();

      var x_begin = this.getNoteHeadBeginX();
      var x_end = this.getNoteHeadEndX();

      if (glyph.flag && render_flag) {
        var note_stem_height = this.stem.getHeight();
        var flag_x, flag_y, flag_code;

        if (this.getStemDirection() === Stem.DOWN) {
          // Down stems have flags on the left.
          flag_x = x_begin + 1;
          flag_y = bounds.y_top - note_stem_height + 2;
          flag_code = glyph.code_flag_downstem;

        } else {
          // Up stems have flags on the left.
          flag_x = x_end + 1;
          flag_y = bounds.y_bottom - note_stem_height - 2;
          flag_code = glyph.code_flag_upstem;
        }

        // Draw the Flag
        Vex.Flow.renderGlyph(ctx, flag_x, flag_y,
            this.render_options.glyph_font_scale, flag_code);
      }
    },

    // Draw the NoteHeads
    drawNoteHeads: function(){
      this.note_heads.forEach(function(note_head) {
        note_head.setContext(this.context).draw();
      }, this);
    },

    // Render the stem onto the canvas
    drawStem: function(stem_struct){
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");

      if (stem_struct) {
        this.setStem(new Stem(stem_struct));
      }
      
      this.stem.setContext(this.context).draw();
    },

    // Draws all the `StaveNote` parts. This is the main drawing method.
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");
      if (!this.stave) throw new Vex.RERR("NoStave",
          "Can't draw without a stave.");
      if (this.ys.length === 0) throw new Vex.RERR("NoYValues",
          "Can't draw note without Y values.");

      var x_begin = this.getNoteHeadBeginX();
      var x_end = this.getNoteHeadEndX();

      var render_stem = this.hasStem() && !this.beam;

      // Format note head x positions
      this.note_heads.forEach(function(note_head) {
        note_head.setX(x_begin);
      }, this);

      // Format stem x positions
      this.stem.setNoteHeadXBounds(x_begin, x_end);

      L("Rendering ", this.isChord() ? "chord :" : "note :", this.keys);

      // Draw each part of the note
      this.drawLedgerLines();
      if (render_stem) this.drawStem();
      this.drawNoteHeads();
      this.drawFlag();
      this.drawModifiers();
    }
  });

  return StaveNote;
}());
// Vex Flow Notation
// Mohit Muthanna <mohit@muthanna.com>
//
// Copyright Mohit Muthanna 2010
//
// Requires vex.js.

/** @constructor */
Vex.Flow.TabNote = (function() {
  function TabNote(tab_struct, draw_stem) {
    if (arguments.length > 0) this.init(tab_struct, draw_stem);
  }

  var Stem = Vex.Flow.Stem;

  Vex.Inherit(TabNote, Vex.Flow.StemmableNote, {
    init: function(tab_struct, draw_stem) {
      var superclass = Vex.Flow.TabNote.superclass;
      superclass.init.call(this, tab_struct);

      this.ghost = false; // Renders parenthesis around notes
      // Note properties
      this.positions = tab_struct.positions; // [{ str: X, fret: X }]
      Vex.Merge(this.render_options, {
        glyph_font_scale: 30, // font size for note heads and rests
        draw_stem: draw_stem,
        draw_dots: draw_stem
      });

      this.glyph =
        Vex.Flow.durationToGlyph(this.duration, this.noteType);
      if (!this.glyph) {
        throw new Vex.RuntimeError("BadArguments",
            "Invalid note initialization data (No glyph found): " +
            JSON.stringify(tab_struct));
      }
      this.buildStem();
      this.setStemDirection(Stem.UP);
      
      this.updateWidth();
    },

    getCategory: function() { return "tabnotes"; },
    setGhost: function(ghost) {
      this.ghost = ghost;
      this.updateWidth();
      return this;
    },

    hasStem: function() {
      return this.render_options.draw_stem;
    },

    getStemExtension: function(){
      var glyph = this.getGlyph();

      if (this.stem_extension_override != null) {
        return this.stem_extension_override;
      }

      if (glyph) {
        return this.getStemDirection() === 1 ? glyph.tabnote_stem_up_extension :
          glyph.tabnote_stem_down_extension;
      }

      return 0;
    },

    addDot: function() {
      var dot = new Vex.Flow.Dot();
      this.dots++;
      return this.addModifier(dot, 0);
    },

    updateWidth: function() {
      this.glyphs = [];
      this.width = 0;
      for (var i = 0; i < this.positions.length; ++i) {
        var fret = this.positions[i].fret;
        if (this.ghost) fret = "(" + fret + ")";
        var glyph = Vex.Flow.tabToGlyph(fret);
        this.glyphs.push(glyph);
        this.width = (glyph.width > this.width) ? glyph.width : this.width;
      }
    },

    setStave: function(stave) {
      var superclass = Vex.Flow.TabNote.superclass;
      superclass.setStave.call(this, stave);
      this.context = stave.context;
      this.width = 0;

      // Calculate the fret number width based on font used
      var i;
      if (this.context) {
        for (i = 0; i < this.glyphs.length; ++i) {
          var text = "" + this.glyphs[i].text;
          if (text.toUpperCase() != "X")
            this.glyphs[i].width = this.context.measureText(text).width;
          this.width = (this.glyphs[i].width > this.width) ?
            this.glyphs[i].width : this.width;
        }
      }

      var ys = [];

      // Setup y coordinates for score.
      for (i = 0; i < this.positions.length; ++i) {
        var line = this.positions[i].str;
        ys.push(this.stave.getYForLine(line - 1));
      }

      return this.setYs(ys);
    },

    // Get the Tab Positions for each note in chord
    getPositions: function() {
      return this.positions;
    },

    addToModifierContext: function(mc) {
      this.setModifierContext(mc);
      for (var i = 0; i < this.modifiers.length; ++i) {
        this.modifierContext.addModifier(this.modifiers[i]);
      }
      this.modifierContext.addModifier(this);
      this.preFormatted = false;
      return this;
    },

    getTieRightX: function() {
      var tieStartX = this.getAbsoluteX();
      var note_glyph_width = this.glyph.head_width;
      tieStartX += (note_glyph_width / 2);
      tieStartX += ((-this.width / 2) + this.width + 2);

      return tieStartX;
    },

    getTieLeftX: function() {
      var tieEndX = this.getAbsoluteX();
      var note_glyph_width = this.glyph.head_width;
      tieEndX += (note_glyph_width / 2);
      tieEndX -= ((this.width / 2) + 2);

      return tieEndX;
    },

    getModifierStartXY: function(position, index) {
      if (!this.preFormatted) throw new Vex.RERR("UnformattedNote",
          "Can't call GetModifierStartXY on an unformatted note");

      if (this.ys.length === 0) throw new Vex.RERR("NoYValues",
          "No Y-Values calculated for this note.");

      var x = 0;
      if (position == Vex.Flow.Modifier.Position.LEFT) {
        x = -1 * 2;  // extra_left_px
      } else if (position == Vex.Flow.Modifier.Position.RIGHT) {
        x = this.width + 2; // extra_right_px
      } else if (position == Vex.Flow.Modifier.Position.BELOW ||
                 position == Vex.Flow.Modifier.Position.ABOVE) {
          var note_glyph_width = this.glyph.head_width;
          x = note_glyph_width / 2;
      }

      return {x: this.getAbsoluteX() + x, y: this.ys[index]};
    },

    getLineForRest: function() {
      return this.positions[0].str;
    },

    // Pre-render formatting
    preFormat: function() {
      if (this.preFormatted) return;
      if (this.modifierContext) this.modifierContext.preFormat();
      // width is already set during init()
      this.setPreFormatted(true);
    },

    getStemX: function() {
      return this.getCenterGlyphX();
    },

    getStemY: function(){
      // The decimal staff line amounts provide optimal spacing between the 
      // fret number and the stem
      var stemUpLine = -0.7;
      var stemDownLine = this.stave.options.num_lines - 0.3;
      var stemStartLine = Stem.UP === this.stem_direction ? stemUpLine : stemDownLine;

      return this.stave.getYForLine(stemStartLine);
    },

    getStemExtents: function() {
      var stem_base_y = this.getStemY();
      var stem_top_y = stem_base_y + (Stem.HEIGHT * -this.stem_direction);

      return { topY: stem_top_y , baseY: stem_base_y};
    },

    draw: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");
      if (!this.stave) throw new Vex.RERR("NoStave", "Can't draw without a stave.");
      if (this.ys.length === 0) throw new Vex.RERR("NoYValues",
          "Can't draw note without Y values.");

      var ctx = this.context;
      var x = this.getAbsoluteX();
      var ys = this.ys;
      var y;

      var render_stem = this.beam == null && this.render_options.draw_stem;
      var render_flag = this.beam == null && render_stem;

      var i;
      for (i = 0; i < this.positions.length; ++i) {
        y = ys[i];

        var glyph = this.glyphs[i];

        // Center the fret text beneath the notation note head
        var note_glyph_width = this.glyph.head_width;
        var tab_x = x + (note_glyph_width / 2) - (glyph.width / 2);

        ctx.clearRect(tab_x - 2, y - 3, glyph.width + 4, 6);

        if (glyph.code) {
          Vex.Flow.renderGlyph(ctx, tab_x, y + 5 + glyph.shift_y,
              this.render_options.glyph_font_scale, glyph.code);
        } else {
          var text = glyph.text.toString();
          ctx.fillText(text, tab_x, y + 5);
        }
      }

      var stem_x = this.getStemX();
      var stem_y = this.getStemY();
      if (render_stem) {
        this.drawStem({
          x_begin: stem_x,
          x_end: stem_x,
          y_top: stem_y,
          y_bottom: stem_y,
          y_extend: 0,
          stem_extension: this.getStemExtension(),
          stem_direction: this.stem_direction
        });
      }

      // Now it's the flag's turn.
      if (this.glyph.flag && render_flag) {
        var flag_x = this.getStemX() + 1 ;
        var flag_y = this.getStemY() - (this.stem.getHeight());
        var flag_code;

        if (this.stem_direction == Stem.DOWN) {
          // Down stems have flags on the left.
          flag_code = this.glyph.code_flag_downstem;
        } else {
          // Up stems have flags on the left.
          flag_code = this.glyph.code_flag_upstem;
        }

        // Draw the Flag
        Vex.Flow.renderGlyph(ctx, flag_x, flag_y,
            this.render_options.glyph_font_scale, flag_code);
      }

      // Draw the modifiers
      this.modifiers.forEach(function(modifier) {
          // Only draw the dots if enabled
          if (modifier.getCategory() === 'dots' && !this.render_options.draw_dots) return;

          modifier.setContext(this.context);
          modifier.draw();
      }, this);
    }
  });

  return TabNote;
}());
// Vex Flow Notation
// Mohit Muthanna <mohit@muthanna.com>
//
// Copyright Mohit Muthanna 2010
//
// Requires vex.js.

/** @constructor */
Vex.Flow.GhostNote = (function() {
  function GhostNote(duration) {
    if (arguments.length > 0) this.init(duration);
  }

  Vex.Inherit(GhostNote, Vex.Flow.StemmableNote, {
    init: function(parameter) {
      // Sanity check
      if (!parameter) {
        throw new Vex.RuntimeError("BadArguments",
            "Ghost note must have valid initialization data to identify " +
            "duration.");
      }

      var note_struct;

      // Preserve backwards-compatibility
      if (typeof(parameter) === "string") {
        note_struct = { duration: parameter };
      } else if (typeof(parameter) === "object") {
        note_struct = parameter;
      } else {
        throw new Vex.RuntimeError("BadArguments",
            "Ghost note must have valid initialization data to identify " +
            "duration.");
      }

      GhostNote.superclass.init.call(this, note_struct);

      // Note properties
      this.setWidth(0);
    },

    isRest: function() { return true; },

    setStave: function(stave) { GhostNote.superclass.setStave.call(this, stave); },

    addToModifierContext: function()
      { /* intentionally overridden */ return this; },

    preFormat: function() {
      this.setPreFormatted(true);
      return this;
    },

    draw: function() {
      if (!this.stave) throw new Vex.RERR("NoStave", "Can't draw without a stave.");

      // Draw the modifiers
      for (var i = 0; i < this.modifiers.length; ++i) {
        var modifier = this.modifiers[i];
        modifier.setContext(this.context);
        modifier.draw();
      }
    }
  });

  return GhostNote;
}());
// Vex Flow Notation
// Copyright Mohit Muthanna 2010
//
// Author Taehoon Moon 2014

/** @constructor */
Vex.Flow.ClefNote = (function() {
  function ClefNote(clef) { this.init(clef); }

  Vex.Inherit(ClefNote, Vex.Flow.Note, {
    init: function(clef) {
      ClefNote.superclass.init.call(this, {duration: "b"});
      
      this.setClef(clef);

      // Note properties
      this.ignore_ticks = true;
    },

    setClef: function(clef) {
      this.clef = Vex.Flow.Clef.types[clef];
      this.glyph = new Vex.Flow.Glyph(this.clef.code, this.clef.point);
      this.setWidth(this.glyph.getMetrics().width);
      return this;
    },

    getClef: function() {
      return this.clef;
    },

    setStave: function(stave) {
      var superclass = Vex.Flow.ClefNote.superclass;
      superclass.setStave.call(this, stave);
    },

    getBoundingBox: function() {
      return new Vex.Flow.BoundingBox(0, 0, 0, 0);
    },

    addToModifierContext: function() {
      /* overridden to ignore */
      return this;
    },

    preFormat: function() {
      this.setPreFormatted(true);
      return this;
    },

    draw: function() {
      if (!this.stave) throw new Vex.RERR("NoStave", "Can't draw without a stave.");
      
      if (!this.glyph.getContext()) {
        this.glyph.setContext(this.context);
      }

      this.glyph.setStave(this.stave);
      this.glyph.setYShift(
        this.stave.getYForLine(this.clef.line) - this.stave.getYForGlyphs());
      this.glyph.renderToStave(this.getAbsoluteX());
    }
  });

  return ClefNote;
}());
// Vex Flow Notation
// Copyright Mohit Muthanna 2010
//
// Author Taehoon Moon 2014

/** @constructor */
Vex.Flow.TimeSigNote = (function() {
  function TimeSigNote(timeSpec, customPadding) {
    if (arguments.length > 0) this.init(timeSpec, customPadding);
  }

  Vex.Inherit(TimeSigNote, Vex.Flow.Note, {
    init: function(timeSpec, customPadding) {
      TimeSigNote.superclass.init.call(this, {duration: "b"});

      var timeSignature = new Vex.Flow.TimeSignature(timeSpec, customPadding);
      this.timeSig = timeSignature.getTimeSig();
      this.setWidth(this.timeSig.glyph.getMetrics().width);

      // Note properties
      this.ignore_ticks = true;
    },

    setStave: function(stave) {
      var superclass = Vex.Flow.TimeSigNote.superclass;
      superclass.setStave.call(this, stave);
    },

    getBoundingBox: function() {
      return new Vex.Flow.BoundingBox(0, 0, 0, 0);
    },

    addToModifierContext: function() {
      /* overridden to ignore */
      return this;
    },

    preFormat: function() {
      this.setPreFormatted(true);
      return this;
    },

    draw: function() {
      if (!this.stave) throw new Vex.RERR("NoStave", "Can't draw without a stave.");
      
      if (!this.timeSig.glyph.getContext()) {
        this.timeSig.glyph.setContext(this.context);
      }

      this.timeSig.glyph.setStave(this.stave);
      this.timeSig.glyph.setYShift(
        this.stave.getYForLine(this.timeSig.line) - this.stave.getYForGlyphs());
      this.timeSig.glyph.renderToStave(this.getAbsoluteX());
    }
  });

  return TimeSigNote;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
// 
// This file implements `Beams` that span over a set of `StemmableNotes`.
// 
// Requires: vex.js, vexmusic.js, note.js
Vex.Flow.Beam = (function() {
  function Beam(notes, auto_stem) {
    if (arguments.length > 0) this.init(notes, auto_stem);
  }

  var Stem = Vex.Flow.Stem;

  // ## Prototype Methods
  Beam.prototype = {
    init: function(notes, auto_stem) {
      if (!notes || notes == []) {
        throw new Vex.RuntimeError("BadArguments", "No notes provided for beam.");
      }

      if (notes.length == 1) {
        throw new Vex.RuntimeError("BadArguments", "Too few notes for beam.");
      }

      // Validate beam line, direction and ticks.
      this.ticks = notes[0].getIntrinsicTicks();

      if (this.ticks >= Vex.Flow.durationToTicks("4")) {
        throw new Vex.RuntimeError("BadArguments",
            "Beams can only be applied to notes shorter than a quarter note.");
      }

      var i; // shared iterator
      var note;

      this.stem_direction = 1;

      for (i = 0; i < notes.length; ++i) {
        note = notes[i];
        if (note.hasStem()) {
          this.stem_direction = note.getStemDirection();
          break;
        }
      }

      var stem_direction = -1;

      // Figure out optimal stem direction based on given notes
      if (auto_stem && notes[0].getCategory() === 'stavenotes')  {
        // Auto Stem StaveNotes
        this.min_line = 1000;

        for (i = 0; i < notes.length; ++i) {
          note = notes[i];
          if (note.getKeyProps) {
            var props = note.getKeyProps();
            var center_line = (props[0].line + props[props.length - 1].line) / 2;
            this.min_line = Math.min(center_line, this.min_line);
          }
        }

        if (this.min_line < 3) stem_direction = 1;
      } else if (auto_stem && notes[0].getCategory() === 'tabnotes') {
        // Auto Stem TabNotes
        var stem_weight = notes.reduce(function(memo, note) {
          return memo + note.stem_direction;
        }, 0);

        stem_direction = stem_weight > -1 ? 1 : -1;
      }

      // Apply stem directions and attach beam to notes
      for (i = 0; i < notes.length; ++i) {
        note = notes[i];
        if (auto_stem) {
          note.setStemDirection(stem_direction);
          this.stem_direction = stem_direction;
        }
        note.setBeam(this);
      }

      this.postFormatted = false;
      this.notes = notes;
      this.beam_count = this.getBeamCount();
      this.break_on_indices = [];
      this.render_options = {
        beam_width: 5,
        max_slope: 0.25,
        min_slope: -0.25,
        slope_iterations: 20,
        slope_cost: 25,
        show_stemlets: false,
        stemlet_extension: 7,
        partial_beam_length: 10
      };
    },

    // The the rendering `context`
    setContext: function(context) { this.context = context; return this; },

    // Get the notes in this beam
    getNotes: function() { return this.notes; },

    // Get the max number of beams in the set of notes
    getBeamCount: function(){
      var beamCounts =  this.notes.map(function(note) {
        return note.getGlyph().beam_count;
      });

      var maxBeamCount =  beamCounts.reduce(function(max, beamCount) {
          return beamCount > max ? beamCount : max;
      });

      return maxBeamCount;
    },

    // Set which note `indices` to break the secondary beam at
    breakSecondaryAt: function(indices) {
      this.break_on_indices = indices;
      return this;
    },

    // Return the y coordinate for linear function
    getSlopeY: function(x, first_x_px, first_y_px, slope) {
      return first_y_px + ((x - first_x_px) * slope);
    },

    // Calculate the best possible slope for the provided notes
    calculateSlope: function() {
      var first_note = this.notes[0];
      var first_y_px = first_note.getStemExtents().topY;
      var first_x_px = first_note.getStemX();

      var inc = (this.render_options.max_slope - this.render_options.min_slope) /
          this.render_options.slope_iterations;
      var min_cost = Number.MAX_VALUE;
      var best_slope = 0;
      var y_shift = 0;

      // iterate through slope values to find best weighted fit
      for (var slope = this.render_options.min_slope;
           slope <= this.render_options.max_slope;
           slope += inc) {
        var total_stem_extension = 0;
        var y_shift_tmp = 0;

        // iterate through notes, calculating y shift and stem extension
        for (var i = 1; i < this.notes.length; ++i) {
          var note = this.notes[i];

          var x_px = note.getStemX();
          var y_px = note.getStemExtents().topY;
          var slope_y_px = this.getSlopeY(x_px, first_x_px, first_y_px, slope) + y_shift_tmp;

          // beam needs to be shifted up to accommodate note
          if (y_px * this.stem_direction < slope_y_px * this.stem_direction) {
            var diff =  Math.abs(y_px - slope_y_px);
            y_shift_tmp += diff * -this.stem_direction;
            total_stem_extension += (diff * i);
          } else { // beam overshoots note, account for the difference
            total_stem_extension += (y_px - slope_y_px) * this.stem_direction;
          }

        }
        /*
          // This causes too many zero-slope beams.

          var cost = this.render_options.slope_cost * Math.abs(slope) +
            Math.abs(total_stem_extension);
        */

        // Pick a beam that minimizes stem extension.
        var cost = Math.abs(total_stem_extension);

        // update state when a more ideal slope is found
        if (cost < min_cost) {
          min_cost = cost;
          best_slope = slope;
          y_shift = y_shift_tmp;
        }
      }

      this.slope = best_slope;
      this.y_shift = y_shift;
    },

    // Create new stems for the notes in the beam, so that each stem
    // extends into the beams.
    applyStemExtensions: function(){
      var first_note = this.notes[0];
      var first_y_px = first_note.getStemExtents().topY;
      var first_x_px = first_note.getStemX();

      for (var i = 0; i < this.notes.length; ++i) {
        var note = this.notes[i];

        var x_px = note.getStemX();
        var y_extents = note.getStemExtents();
        var base_y_px = y_extents.baseY;
        var top_y_px = y_extents.topY;

        // For harmonic note heads, shorten stem length by 3 pixels
        base_y_px += this.stem_direction * note.glyph.stem_offset;

        // Don't go all the way to the top (for thicker stems)
        var y_displacement = Vex.Flow.STEM_WIDTH;

        if (!note.hasStem()) {
          if (note.isRest() && this.render_options.show_stemlets) {
            var centerGlyphX = note.getCenterGlyphX();

            var width = this.render_options.beam_width;
            var total_width = ((this.beam_count - 1)* width * 1.5) + width;

            var stemlet_height = (total_width - y_displacement +
              this.render_options.stemlet_extension);

            var beam_y = this.getSlopeY(centerGlyphX, first_x_px,
                            first_y_px, this.slope) + this.y_shift;
            var start_y = beam_y + (Vex.Flow.Stem.HEIGHT * this.stem_direction);
            var end_y = beam_y + (stemlet_height * this.stem_direction);

            // Draw Stemlet
            note.setStem(new Vex.Flow.Stem({
              x_begin: centerGlyphX,
              x_end: centerGlyphX,
              y_bottom: this.stem_direction === 1 ? end_y : start_y,
              y_top: this.stem_direction === 1 ? start_y : end_y,
              y_extend: y_displacement,
              stem_extension: -1, // To avoid protruding through the beam
              stem_direction: this.stem_direction
            }));
          }

          continue;
        }

        var slope_y = this.getSlopeY(x_px, first_x_px, first_y_px,
                        this.slope) + this.y_shift;

        note.setStem(new Vex.Flow.Stem({
          x_begin: x_px - (Vex.Flow.STEM_WIDTH/2),
          x_end: x_px,
          y_top: this.stem_direction === 1 ? top_y_px : base_y_px,
          y_bottom: this.stem_direction === 1 ? base_y_px :  top_y_px ,
          y_extend: y_displacement,
          stem_extension: Math.abs(top_y_px - slope_y) - Stem.HEIGHT - 1,
          stem_direction: this.stem_direction
        }));
      }
    },

    // Get the x coordinates for the beam lines of specific `duration`
    getBeamLines: function(duration) {
      var beam_lines = [];
      var beam_started = false;
      var current_beam;
      var partial_beam_length = this.render_options.partial_beam_length;

      function determinePartialSide (prev_note, next_note){
          // Compare beam counts and store differences
          var unshared_beams = 0;
          if (next_note && prev_note) {
            unshared_beams = prev_note.getBeamCount() - next_note.getBeamCount();
          }

          var left_partial = duration !== "8" && unshared_beams > 0;
          var right_partial = duration !== "8" && unshared_beams < 0;

          return {
            left: left_partial,
            right: right_partial
          };
        }

      for (var i = 0; i < this.notes.length; ++i) {
        var note = this.notes[i];
        var prev_note = this.notes[i-1];
        var next_note = this.notes[i+1];
        var ticks = note.getIntrinsicTicks();
        var partial = determinePartialSide(prev_note, next_note);
        var stem_x = note.isRest() ? note.getCenterGlyphX() : note.getStemX();

        // Check whether to apply beam(s)
        if (ticks < Vex.Flow.durationToTicks(duration)) {
          if (!beam_started) {
            var new_line = {start: stem_x, end: null};

            if (partial.left) {
              new_line.end = stem_x - partial_beam_length;
            }

            beam_lines.push(new_line);
            beam_started = true;
          } else {
            current_beam = beam_lines[beam_lines.length - 1];
            current_beam.end = stem_x;

            // Should break secondary beams on note
            var should_break = this.break_on_indices.indexOf(i) !== -1;
            // Shorter than or eq an 8th note duration
            var can_break = parseInt(duration, 10) >= 8;
            if (should_break  && can_break) {
              beam_started = false;
            }
          }
        } else {
          if (!beam_started) {
            // we don't care
          } else {
            current_beam = beam_lines[beam_lines.length - 1];
            if (current_beam.end == null) {
              // single note
              current_beam.end = current_beam.start +
                                 partial_beam_length;
            } else {
              // we don't care
            }
          }

          beam_started = false;
        }
      }

      if (beam_started === true) {
        current_beam = beam_lines[beam_lines.length - 1];
        if (current_beam.end == null) {
          // single note
          current_beam.end = current_beam.start -
              partial_beam_length;
        }
      }

      return beam_lines;
    },

    // Render the stems for each notes
    drawStems: function() {
      this.notes.forEach(function(note) {
        if (note.getStem()) {
          note.getStem().setContext(this.context).draw();
        }
      }, this);
    },

    // Render the beam lines
    drawBeamLines: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");

      var valid_beam_durations = ["4", "8", "16", "32", "64"];

      var first_note = this.notes[0];
      var last_note = this.notes[this.notes.length - 1];

      var first_y_px = first_note.getStemExtents().topY;
      var last_y_px = last_note.getStemExtents().topY;

      var first_x_px = first_note.getStemX();

      var beam_width = this.render_options.beam_width * this.stem_direction;

      // Draw the beams.
      for (var i = 0; i < valid_beam_durations.length; ++i) {
        var duration = valid_beam_durations[i];
        var beam_lines = this.getBeamLines(duration);

        for (var j = 0; j < beam_lines.length; ++j) {
          var beam_line = beam_lines[j];
          var first_x = beam_line.start - (this.stem_direction == -1 ? Vex.Flow.STEM_WIDTH/2:0);
          var first_y = this.getSlopeY(first_x, first_x_px, first_y_px, this.slope);

          var last_x = beam_line.end +
            (this.stem_direction == 1 ? (Vex.Flow.STEM_WIDTH/3):(-Vex.Flow.STEM_WIDTH/3));
          var last_y = this.getSlopeY(last_x, first_x_px, first_y_px, this.slope);

          this.context.beginPath();
          this.context.moveTo(first_x, first_y + this.y_shift);
          this.context.lineTo(first_x, first_y + beam_width + this.y_shift);
          this.context.lineTo(last_x + 1, last_y + beam_width + this.y_shift);
          this.context.lineTo(last_x + 1, last_y + this.y_shift);
          this.context.closePath();
          this.context.fill();
        }

        first_y_px += beam_width * 1.5;
        last_y_px += beam_width * 1.5;
      }
    },

    // Pre-format the beam
    preFormat: function() { return this; },

    // Post-format the beam. This can only be called after
    // the notes in the beam have both `x` and `y` values. ie: they've 
    // been formatted and have staves
    postFormat: function() {
      if (this.postFormatted) return;

      this.calculateSlope();
      this.applyStemExtensions();

      this.postFormatted = true;
    },

    // Render the beam to the canvas context
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");

      if (this.unbeamable) return;

      if (!this.postFormatted) {
        this.postFormat();
      }

      this.drawStems();
      this.drawBeamLines();

      return true;
    }
  };

  // ## Static Methods
  // 
  // Gets the default beam groups for a provided time signature.
  // Attempts to guess if the time signature is not found in table.
  // Currently this is fairly naive.
  Beam.getDefaultBeamGroups = function(time_sig){
    if (!time_sig || time_sig == "c") time_sig = "4/4";

    var defaults = {
      '1/2' :  ['1/2'],
      '2/2' :  ['1/2'],
      '3/2' :  ['1/2'],
      '4/2' :  ['1/2'],

      '1/4' :  ['1/4'],
      '2/4' :  ['1/4'],
      '3/4' :  ['1/4'],
      '4/4' :  ['1/4'],

      '1/8' :  ['1/8'],
      '2/8' :  ['2/8'],
      '3/8' :  ['3/8'],
      '4/8' :  ['2/8'],

      '1/16' : ['1/16'],
      '2/16' : ['2/16'],
      '3/16' : ['3/16'],
      '4/16' : ['2/16']
    };

    var Fraction = Vex.Flow.Fraction;
    var groups = defaults[time_sig];

    if (!groups) {
      // If no beam groups found, naively determine
      // the beam groupings from the time signature
      var beatTotal = parseInt(time_sig.split('/')[0], 10);
      var beatValue = parseInt(time_sig.split('/')[1], 10);

      var tripleMeter = beatTotal % 3 === 0;

      if (tripleMeter) {
        return [new Fraction(3, beatValue)];
      } else if (beatValue > 4) {
        return [new Fraction(2, beatValue)];
      } else if (beatValue <= 4) {
        return [new Fraction(1, beatValue)];
      }
    } else {
      return groups.map(function(group) {
        return new Fraction().parse(group);
      });
    }
  };

  // A helper function to automatically build basic beams for a voice. For more
  // complex auto-beaming use `Beam.generateBeams()`.
  // 
  // Parameters:
  // * `voice` - The voice to generate the beams for
  // * `stem_direction` - A stem direction to apply to the entire voice
  // * `groups` - An array of `Fraction` representing beat groupings for the beam
  Beam.applyAndGetBeams = function(voice, stem_direction, groups) {
    return Beam.generateBeams(voice.getTickables(), {
      groups: groups,
      stem_direction: stem_direction
    });
  };

  // A helper function to autimatically build beams for a voice with 
  // configuration options.
  // 
  // Example configuration object:
  //
  // ```
  // config = {
  //   groups: [new Vex.Flow.Fraction(2, 8)],
  //   stem_direction: -1,
  //   beam_rests: true,
  //   beam_middle_only: true,
  //   show_stemlets: false
  // };
  // ```
  // 
  // Parameters:
  // * `notes` - An array of notes to create the beams for
  // * `config` - The configuration object
  //    * `groups` - Array of `Fractions` that represent the beat structure to beam the notes
  //    * `stem_direction` - Set to apply the same direction to all notes
  //    * `beam_rests` - Set to `true` to include rests in the beams
  //    * `beam_middle_only` - Set to `true` to only beam rests in the middle of the beat
  //    * `show_stemlets` - Set to `true` to draw stemlets for rests 
  // 
  Beam.generateBeams = function(notes, config) {

    if (!config) config = {};

    if (!config.groups || !config.groups.length) {
      config.groups = [new Vex.Flow.Fraction(2, 8)];
    }

    // Convert beam groups to tick amounts
    var tickGroups = config.groups.map(function(group) {
      if (!group.multiply) {
        throw new Vex.RuntimeError("InvalidBeamGroups",
          "The beam groups must be an array of Vex.Flow.Fractions");
      }
      return group.clone().multiply(Vex.Flow.RESOLUTION, 1);
    });

    var unprocessedNotes = notes;
    var currentTickGroup = 0;
    var noteGroups       = [];
    var currentGroup     = [];

    function getTotalTicks(vf_notes){
      return vf_notes.reduce(function(memo,note){
        return note.getTicks().clone().add(memo);
      }, new Vex.Flow.Fraction(0, 1));
    }

    function nextTickGroup() {
      if (tickGroups.length - 1 > currentTickGroup) {
        currentTickGroup += 1;
      } else {
        currentTickGroup = 0;
      }
    }

    function createGroups(){
      var nextGroup = [];

      unprocessedNotes.forEach(function(unprocessedNote){
        nextGroup    = [];
        if (unprocessedNote.shouldIgnoreTicks()) {
          noteGroups.push(currentGroup);
          currentGroup = nextGroup;
          return; // Ignore untickables (like bar notes)
        }

        currentGroup.push(unprocessedNote);
        var ticksPerGroup = tickGroups[currentTickGroup].value();
        var totalTicks = getTotalTicks(currentGroup).value();

        // Double the amount of ticks in a group, if it's an unbeamable tuplet
        if (parseInt(unprocessedNote.duration, 10) < 8 && unprocessedNote.tuplet) {
          ticksPerGroup *= 2;
        }

        // If the note that was just added overflows the group tick total
        if (totalTicks > ticksPerGroup) {
          nextGroup.push(currentGroup.pop());
          noteGroups.push(currentGroup);
          currentGroup = nextGroup;
          nextTickGroup();
        } else if (totalTicks == ticksPerGroup) {
          noteGroups.push(currentGroup);
          currentGroup = nextGroup;
          nextTickGroup();
        }
      });

      // Adds any remainder notes
      if (currentGroup.length > 0)
        noteGroups.push(currentGroup);
    }

    function getBeamGroups() {
      return noteGroups.filter(function(group){
          if (group.length > 1) {
            var beamable = true;
            group.forEach(function(note) {
              if (note.getIntrinsicTicks() >= Vex.Flow.durationToTicks("4")) {
                beamable = false;
              }
            });
            return beamable;
          }
          return false;
      });
    }

    // Splits up groups by Rest
    function sanitizeGroups() {
      var sanitizedGroups = [];
      noteGroups.forEach(function(group) {
        var tempGroup = [];
        group.forEach(function(note, index, group) {
          var isFirstOrLast = index === 0 || index === group.length - 1;

          var breaksOnEachRest = !config.beam_rests && note.isRest();
          var breaksOnFirstOrLastRest = (config.beam_rests &&
            config.beam_middle_only && note.isRest() && isFirstOrLast);

          var shouldBreak = breaksOnEachRest || breaksOnFirstOrLastRest;

          if (shouldBreak) {
            if (tempGroup.length > 0) {
              sanitizedGroups.push(tempGroup);
            }
            tempGroup = [];
          } else {
            tempGroup.push(note);
          }
        });

        if (tempGroup.length > 0) {
          sanitizedGroups.push(tempGroup);
        }
      });

      noteGroups = sanitizedGroups;
    }

    function formatStems() {
      noteGroups.forEach(function(group){
        var stemDirection = determineStemDirection(group);
        applyStemDirection(group, stemDirection);
      });
    }

    function determineStemDirection(group) {
      if (config.stem_direction) return config.stem_direction;

      var lineSum = 0;
      group.forEach(function(note) {
        if (note.keyProps) {
          note.keyProps.forEach(function(keyProp){
            lineSum += (keyProp.line - 2.5);
          });
        }
      });

      if (lineSum > 0)
        return -1;
      return 1;
    }

    function applyStemDirection(group, direction) {
      group.forEach(function(note){
        if (note.hasStem()) note.setStemDirection(direction);
      });
    }

    function getTupletGroups() {
      return noteGroups.filter(function(group){
        if (group[0]) return group[0].tuplet;
      });
    }


    // Using closures to store the variables throughout the various functions
    // IMO Keeps it this process lot cleaner - but not super consistent with
    // the rest of the API's style - Silverwolf90 (Cyril)
    createGroups();
    sanitizeGroups();
    formatStems();

    // Get the notes to be beamed
    var beamedNoteGroups = getBeamGroups();

    // Get the tuplets in order to format them accurately
    var tupletGroups = getTupletGroups();

    // Create a Vex.Flow.Beam from each group of notes to be beamed
    var beams = [];
    beamedNoteGroups.forEach(function(group){
      var beam = new Vex.Flow.Beam(group);

      if (config.show_stemlets) {
        beam.render_options.show_stemlets = true;
      }

      beams.push(beam);
    });

    // Reformat tuplets
    tupletGroups.forEach(function(group){
      var firstNote = group[0];
      for (var i=0; i<group.length; ++i) {
        if (group[i].hasStem()) {
          firstNote = group[i];
          break;
        }
      }

      var tuplet = firstNote.tuplet;

      if (firstNote.beam) tuplet.setBracketed(false);
      if (firstNote.stem_direction == -1) {
        tuplet.setTupletLocation(Vex.Flow.Tuplet.LOCATION_BOTTOM);
      }
    });

    return beams;
  };

  return Beam;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
// 
// This file implements the main Voice class. It's mainly a container 
// object to group `Tickables` for formatting.
Vex.Flow.Voice = (function() {
  function Voice(time) {
    if (arguments.length > 0) this.init(time);
  }

  // Modes allow the addition of ticks in three different ways:
  //
  // STRICT: This is the default. Ticks must fill the voice.
  // SOFT:   Ticks can be added without restrictions.
  // FULL:   Ticks do not need to fill the voice, but can't exceed the maximum
  //         tick length.
  Voice.Mode = {
    STRICT: 1,
    SOFT:   2,
    FULL:   3
  };

  // ## Prototype Methods
  Voice.prototype = {
    init: function(time) {
      this.time = Vex.Merge({
        num_beats: 4,
        beat_value: 4,
        resolution: Vex.Flow.RESOLUTION
      }, time);

      // Recalculate total ticks.
      this.totalTicks = new Vex.Flow.Fraction(
        this.time.num_beats * (this.time.resolution / this.time.beat_value), 1);

      this.resolutionMultiplier = 1;

      // Set defaults
      this.tickables = [];
      this.ticksUsed = new Vex.Flow.Fraction(0, 1);
      this.smallestTickCount = this.totalTicks.clone();
      this.largestTickWidth = 0;
      this.stave = null;
      this.boundingBox = null;
      // Do we care about strictly timed notes
      this.mode = Vex.Flow.Voice.Mode.STRICT;

      // This must belong to a VoiceGroup
      this.voiceGroup = null;
    },

    // Get the total ticks in the voice
    getTotalTicks: function() { return this.totalTicks; },

    // Get the total ticks used in the voice by all the tickables
    getTicksUsed: function() { return this.ticksUsed; },

    // Get the largest width of all the tickables
    getLargestTickWidth: function() { return this.largestTickWidth; },

    // Get the tick count for the shortest tickable
    getSmallestTickCount: function() { return this.smallestTickCount; },

    // Get the tickables in the voice
    getTickables: function() { return this.tickables; },

    // Get/set the voice mode, use a value from `Voice.Mode`
    getMode: function() { return this.mode; },
    setMode: function(mode) { this.mode = mode; return this; },

    // Get the resolution multiplier for the voice
    getResolutionMultiplier: function() { return this.resolutionMultiplier; },

    // Get the actual tick resolution for the voice
    getActualResolution: function() { return this.resolutionMultiplier * this.time.resolution; },

    // Set the voice's stave
    setStave: function(stave) {
      this.stave = stave;
      this.boundingBox = null; // Reset bounding box so we can reformat
      return this;
    },

    // Get the bounding box for the voice
    getBoundingBox: function() {
      if (!this.boundingBox) {
        if (!this.stave) throw Vex.RERR("NoStave", "Can't get bounding box without stave.");
        var stave = this.stave;

        var boundingBox = null;
        if (this.tickables[0]) {
          this.tickables[0].setStave(stave);
          boundingBox = this.tickables[0].getBoundingBox();
        }

        for (var i = 0; i < this.tickables.length; ++i) {
          this.tickables[i].setStave(stave);
          if (i > 0 && boundingBox) {
            var bb = this.tickables[i].getBoundingBox();
            if (bb) boundingBox.mergeWith(bb);
          }
        }

        this.boundingBox = boundingBox;
      }
      return this.boundingBox;
    },

    // Every tickable must be associated with a voiceGroup. This allows formatters
    // and preformatters to associate them with the right modifierContexts.
    getVoiceGroup: function() {
      if (!this.voiceGroup)
        throw new Vex.RERR("NoVoiceGroup", "No voice group for voice.");
      return this.voiceGroup;
    },

    // Set the voice group
    setVoiceGroup: function(g) { this.voiceGroup = g; return this; },

    // Set the voice mode to strict or soft 
    setStrict: function(strict) {
      this.mode = strict ? Vex.Flow.Voice.Mode.STRICT : Vex.Flow.Voice.Mode.SOFT;
      return this;
    },

    // Determine if the voice is complete according to the voice mode
    isComplete: function() {
      if (this.mode == Vex.Flow.Voice.Mode.STRICT ||
          this.mode == Vex.Flow.Voice.Mode.FULL) {
        return this.ticksUsed.equals(this.totalTicks);
      } else {
        return true;
      }
    },

    // Add a tickable to the voice
    addTickable: function(tickable) {
      if (!tickable.shouldIgnoreTicks()) {
        var ticks = tickable.getTicks();

        // Update the total ticks for this line
        this.ticksUsed.add(ticks);

        if ((this.mode == Vex.Flow.Voice.Mode.STRICT ||
             this.mode == Vex.Flow.Voice.Mode.FULL) &&
             this.ticksUsed.value() > this.totalTicks.value()) {
          this.totalTicks.subtract(ticks);
          throw new Vex.RERR("BadArgument", "Too many ticks.");
        }

        // Track the smallest tickable for formatting
        if (ticks.value() < this.smallestTickCount.value()) {
          this.smallestTickCount = ticks.clone();
        }

        this.resolutionMultiplier = this.ticksUsed.denominator;

        // Expand total ticks using denominator from ticks used
        this.totalTicks.add(0, this.ticksUsed.denominator);
      }

      // Add the tickable to the line
      this.tickables.push(tickable);
      tickable.setVoice(this);
      return this;
    },

    // Add an array of tickables to the voice
    addTickables: function(tickables) {
      for (var i = 0; i < tickables.length; ++i) {
        this.addTickable(tickables[i]);
      }

      return this;
    },

    // Preformats the voice by applying the voice's stave to each note
    preFormat: function(){
      if (this.preFormatted) return;

      this.tickables.forEach(function(tickable) {
        if (!tickable.getStave()) {
          tickable.setStave(this.stave);
        }
      }, this);

      this.preFormatted = true;
      return this;
    },

    // Render the voice onto the canvas `context` and an optional `stave`.
    // If `stave` is omitted, it is expected that the notes have staves
    // already set.
    draw: function(context, stave) {
      var boundingBox = null;
      for (var i = 0; i < this.tickables.length; ++i) {
        var tickable = this.tickables[i];

        // Set the stave if provided
        if (stave) tickable.setStave(stave);

        if (!tickable.getStave()) {
          throw new Vex.RuntimeError("MissingStave",
            "The voice cannot draw tickables without staves.");
        }

        if (i === 0) boundingBox = tickable.getBoundingBox();

        if (i > 0 && boundingBox) {
          var tickable_bb = tickable.getBoundingBox();
          if (tickable_bb) boundingBox.mergeWith(tickable_bb);
        }

       tickable.setContext(context);
       tickable.draw();
      }

      this.boundingBox = boundingBox;
    }
  };

  return Voice;
}());// Vex Music Notation
// Mohit Muthanna <mohit@muthanna.com>
//
// Copyright Mohit Muthanna 2010

/** @constructor */
Vex.Flow.VoiceGroup = (function() {
  function VoiceGroup() {
    this.init();
  }

  VoiceGroup.prototype = {
    init: function() {
      this.voices = [];
      this.modifierContexts = [];
    },

    // Every tickable must be associated with a voiceGroup. This allows formatters
    // and preformatters to associate them with the right modifierContexts.
    getVoices: function() { return this.voices; },
    getModifierContexts: function() { return this.modifierContexts; },

    addVoice: function(voice) {
      if (!voice) throw new Vex.RERR("BadArguments", "Voice cannot be null.");
      this.voices.push(voice);
      voice.setVoiceGroup(this);
    }
  };

  return VoiceGroup;
}());// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// `Modifier` is an abstract interface for notational elements that modify
// a `Note`. Examples of modifiers are `Accidental`, `Annotation`, `Stroke`, etc.
//
// For a `Modifier` instance to be positioned correctly, it must be part of
// a `ModifierContext`. All modifiers in the same context are rendered relative to
// one another.
//
// Typically, all modifiers to a note are part of the same `ModifierContext` instance. Also,
// in multi-voice staves, all modifiers to notes on the same `tick` are part of the same
// `ModifierContext`. This ensures that multiple voices don't trample all over each other.

Vex.Flow.Modifier = (function() {
  function Modifier() { this.init(); }
    // To enable logging for this class. Set `Vex.Flow.Modifier.DEBUG` to `true`.
  function L() { if (Modifier.DEBUG) Vex.L("Vex.Flow.Modifier", arguments); }

  // Modifiers can be positioned almost anywhere, relative to a note.
  Modifier.Position = {
    LEFT: 1,
    RIGHT: 2,
    ABOVE: 3,
    BELOW: 4
  };

  // ## Prototype Methods
  Modifier.prototype = {

    // The constructor sets initial widhts and constants.
    init: function() {
      this.width = 0;
      this.context = null;

      // Modifiers are attached to a note and an index. An index is a
      // specific head in a chord.
      this.note = null;
      this.index = null;

      // The `text_line` is reserved space above or below a stave.
      this.text_line = 0;
      this.position = Modifier.Position.LEFT;
      this.modifier_context = null;
      this.x_shift = 0;
      this.y_shift = 0;
      L("Created new modifier");
    },

    // Every modifier has a category. The `ModifierContext` uses this to determine
    // the type and order of the modifiers.
    getCategory: function() { return "none"; },

    // Get and set modifier widths.
    getWidth: function() { return this.width; },
    setWidth: function(width) { this.width = width; return this; },

    // Get and set attached note (`StaveNote`, `TabNote`, etc.)
    getNote: function() { return this.note; },
    setNote: function(note) { this.note = note; return this; },

    // Get and set note index, which is a specific note in a chord.
    getIndex: function() { return this.index; },
    setIndex: function(index) { this.index = index; return this; },

    // Get and set rendering context.
    getContext: function() { return this.context; },
    setContext: function(context) { this.context = context; return this; },

    // Every modifier must be part of a `ModifierContext`.
    getModifierContext: function() { return this.modifier_context; },
    setModifierContext: function(c) { this.modifier_context = c; return this; },

    // Get and set articulation position.
    getPosition: function() { return this.position; },
    setPosition: function(position) { this.position = position; return this; },

    // Set the `text_line` for the modifier.
    setTextLine: function(line) { this.text_line = line; return this; },

    // Shift modifier down `y` pixels. Negative values shift up.
    setYShift: function(y) { this.y_shift = y; return this; },

    // Shift modifier `x` pixels in the direction of the modifier. Negative values
    // shift reverse.
    setXShift: function(x) {
      this.x_shift = 0;
      if (this.position == Modifier.Position.LEFT) {
        this.x_shift -= x;
      } else {
        this.x_shift += x;
      }
    },

    // Render the modifier onto the canvas.
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");
      throw new Vex.RERR("MethodNotImplemented",
          "Draw() not implemented for this modifier.");
    }
  };

  return Modifier;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements various types of modifiers to notes (e.g. bends,
// fingering positions etc.) Accidentals should also be implemented as
// modifiers, eventually.

/**
 * @constructor
 */
Vex.Flow.ModifierContext = (function() {
  function ModifierContext() {
    // Current modifiers
    this.modifiers = {};

    // Formatting data.
    this.preFormatted = false;
    this.postFormatted = false;
    this.width = 0;
    this.spacing = 0;
    this.state = {
      left_shift: 0,
      right_shift: 0,
      text_line: 0
    };
  }

  // Static method. Called from formatNotes :: shift rests vertically
  var shiftRestVertical = function(rest, note, dir) {
    if (!Vex.Debug) return;

    var delta = 0;
    var padding;

    if (dir == 1) {
      padding = note.isrest ? 0.0 : 0.5;
      delta = note.max_line - rest.min_line;
      delta += padding;
    } else {
      padding = note.isrest ? 0.0 : 0.5;
      delta = note.min_line - rest.max_line;
      delta -= padding;
    }

    rest.line += delta;
    rest.max_line += delta;
    rest.min_line += delta;
    rest.note.keyProps[0].line += delta;
  };

// Called from formatNotes :: center a rest between two notes
  var centerRest = function(rest, noteU, noteL) {
    var delta = rest.line - Vex.MidLine(noteU.min_line, noteL.max_line);
    rest.note.keyProps[0].line -= delta;
    rest.line -= delta;
    rest.max_line -= delta;
    rest.min_line -= delta;
  };

  ModifierContext.prototype = {
    addModifier: function(modifier) {
      var type = modifier.getCategory();
      if (!this.modifiers[type]) this.modifiers[type] = [];
      this.modifiers[type].push(modifier);
      modifier.setModifierContext(this);
      this.preFormatted = false;
      return this;
    },

    getModifiers: function(type) { return this.modifiers[type]; },

    getWidth: function() { return this.width; },

    getExtraLeftPx: function() { return this.state.left_shift; },

    getExtraRightPx: function() { return this.state.right_shift; },

    getMetrics: function() {
      if (!this.formatted) throw new Vex.RERR("UnformattedModifier",
          "Unformatted modifier has no metrics.");

      return {
        width: this.state.left_shift + this.state.right_shift + this.spacing,
        spacing: this.spacing,
        extra_left_px: this.state.left_shift,
        extra_right_px: this.state.right_shift
      };
    },

    formatNotes: function() {
      var notes = this.modifiers['stavenotes'];
      if (!notes || notes.length < 2) return this;

      if (notes[0].getStave() != null)
        return this.formatNotesByY(notes);

      var notes_list= [];

      for (var i = 0; i < notes.length; i++) {
        var props = notes[i].getKeyProps();
        var line = props[0].line;
        var minL = props[props.length -1].line;
        var stem_dir = notes[i].getStemDirection();
        var stem_max = notes[i].getStemLength() / 10;
        var stem_min = notes[i].getStemMinumumLength() / 10;

        var maxL;
        if (notes[i].isRest()) {
          maxL = line + notes[i].glyph.line_above;
          minL = line - notes[i].glyph.line_below;
        } else {
          maxL = stem_dir == 1 ? props[props.length -1].line + stem_max
               : props[props.length -1].line;
          minL = stem_dir == 1 ? props[0].line
               : props[0].line - stem_max;
        }
        notes_list.push(
          {line: props[0].line,         // note/rest base line
           max_line: maxL,              // note/rest upper bounds line
           min_line: minL,              // note/rest lower bounds line
           isrest: notes[i].isRest(),
           stem_dir: stem_dir,
           stem_max: stem_max,          // Maximum (default) note stem length;
           stem_min: stem_min,          // minimum note stem length
           voice_shift: notes[i].getVoiceShiftWidth(),
           is_displaced: notes[i].isDisplaced(),   // note manually displaced
           note: notes[i]});
      }

      var voices = notes_list.length;

      var noteU = notes_list[0];
      var noteM = voices > 2 ? notes_list[1] : null;
      var noteL = voices > 2 ? notes_list[2] : notes_list[1];

      // for two voice backward compatibility, ensure upper voice is stems up
      // for three voices, the voices must be in order (upper, middle, lower)
      if (voices == 2 && noteU.stem_dir == -1 && noteL.stem_dir == 1) {
        noteU = notes_list[1];
        noteL = notes_list[0];
      }

      var voice_x_shift = Math.max(noteU.voice_shift, noteL.voice_shift);
      var x_shift = 0;
      var stem_delta;

      // Test for two voice note intersection
      if (voices == 2) {
        var line_spacing = noteU.stem_dir == noteL.stem_dir ? 0.0 : 0.5;
        // if top voice is a middle voice, check stem intersection with lower voice
        if (noteU.stem_dir == noteL.stem_dir &&
            noteU.min_line <= noteL.max_line) {
          if (!noteU.isrest) {
            stem_delta = Math.abs(noteU.line - (noteL.max_line + 0.5));
            stem_delta = Math.max(stem_delta, noteU.stem_min);
            noteU.min_line = noteU.line - stem_delta;
            noteU.note.setStemLength(stem_delta * 10);
          }
        }
        if (noteU.min_line <= noteL.max_line + line_spacing) {
          if (noteU.isrest)
            // shift rest up
            shiftRestVertical(noteU, noteL, 1);
          else if (noteL.isrest)
            // shift rest down
            shiftRestVertical(noteL, noteU, -1);
          else {
            x_shift = voice_x_shift;
            if (noteU.stem_dir == noteL.stem_dir)
              // upper voice is middle voice, so shift it right
              noteU.note.setXShift(x_shift + 3);
            else
              // shift lower voice right
              noteL.note.setXShift(x_shift);
          }
        }

        // format complete
        return this;
      }

      // Check middle voice stem intersection with lower voice
      if (noteM != null && noteM.min_line < noteL.max_line + 0.5) {
        if (!noteM.isrest) {
          stem_delta = Math.abs(noteM.line - (noteL.max_line + 0.5));
          stem_delta = Math.max(stem_delta, noteM.stem_min);
          noteM.min_line = noteM.line - stem_delta;
          noteM.note.setStemLength(stem_delta * 10);
        }
      }

      // For three voices, test if rests can be repositioned
      //
      // Special case 1 :: middle voice rest between two notes
      //
      if (noteM.isrest && !noteU.isrest && !noteL.isrest) {
        if (noteU.min_line <= noteM.max_line ||
            noteM.min_line <= noteL.max_line) {
           var rest_height = noteM.max_line - noteM.min_line;
           var space = noteU.min_line - noteL.max_line;
           if (rest_height < space)
             // center middle voice rest between the upper and lower voices
             centerRest(noteM, noteU, noteL);
           else {
             x_shift = voice_x_shift + 3;    // shift middle rest right
             noteM.note.setXShift(x_shift);
           }
           // format complete
           return this;
        }
      }

      // Special case 2 :: all voices are rests
      if (noteU.isrest && noteM.isrest && noteL.isrest) {
        // Shift upper voice rest up
        shiftRestVertical(noteU, noteM, 1);
        // Shift lower voice rest down
        shiftRestVertical(noteL, noteM, -1);
        // format complete
        return this;
      }

      // Test if any other rests can be repositioned
      if (noteM.isrest && noteU.isrest && noteM.min_line <= noteL.max_line)
        // Shift middle voice rest up
        shiftRestVertical(noteM, noteL, 1);
      if (noteM.isrest && noteL.isrest && noteU.min_line <= noteM.max_line)
        // Shift middle voice rest down
        shiftRestVertical(noteM, noteU, -1);
      if (noteU.isrest && noteU.min_line <= noteM.max_line)
        // shift upper voice rest up;
        shiftRestVertical(noteU, noteM, 1);
      if (noteL.isrest && noteM.min_line <= noteL.max_line)
        // shift lower voice rest down
        shiftRestVertical(noteL, noteM, -1);

      // If middle voice intersects upper or lower voice
      if ((!noteU.isrest && !noteM.isrest && noteU.min_line <= noteM.max_line + 0.5) ||
          (!noteM.isrest && !noteL.isrest && noteM.min_line <= noteL.max_line)) {
        x_shift = voice_x_shift + 3;      // shift middle note right
        noteM.note.setXShift(x_shift);
      }

      // Format complete
      return this;

    },

    formatNotesByY: function(notes) {
      // NOTE: this function does not support more than two voices per stave
      //       use with care.
      var hasStave = true;
      var i;

      for (i = 0; i < notes.length; i++) {
        hasStave = hasStave && notes[i].getStave() != null;
      }

      if (!hasStave) throw new Vex.RERR("Stave Missing",
        "All notes must have a stave - Vex.Flow.ModifierContext.formatMultiVoice!");

      var x_shift = 0;

      for (i = 0; i < notes.length - 1; i++) {
        var top_note = notes[i];
        var bottom_note = notes[i + 1];

        if (top_note.getStemDirection() == Vex.Flow.StaveNote.STEM_DOWN) {
          top_note = notes[i + 1];
          bottom_note = notes[i];
        }

        var top_keys = top_note.getKeyProps();
        var bottom_keys = bottom_note.getKeyProps();

        var topY = top_note.getStave().getYForLine(top_keys[0].line);
        var bottomY = bottom_note.getStave().getYForLine(bottom_keys[bottom_keys.length - 1].line);

        var line_space = top_note.getStave().options.spacing_between_lines_px;
        if (Math.abs(topY - bottomY) == line_space / 2) {
          x_shift = top_note.getVoiceShiftWidth();
          bottom_note.setXShift(x_shift);
        }
      }

      this.state.right_shift += x_shift;
      return this;
    },

    formatDots: function() {
      var right_shift = this.state.right_shift;
      var dots = this.modifiers['dots'];
      var dot_spacing = 1;

      if (!dots || dots.length === 0) return this;

      var i, dot, note, shift;
      var dot_list = [];
      for (i = 0; i < dots.length; ++i) {
        dot = dots[i];
        note = dot.getNote();

        var props;
        // Only StaveNote has .getKeyProps()
        if (typeof note.getKeyProps === 'function') {
          props = note.getKeyProps()[dot.getIndex()];
          shift = (props.displaced ? note.getExtraRightPx() : 0);
        } else { // Else it's a TabNote
          props = { line: 0.5 }; // Shim key props for dot placement
          shift = 0;
        }

        dot_list.push({ line: props.line, shift: shift, note: note, dot: dot });
      }

      // Sort dots by line number.
      dot_list.sort(function(a, b) { return (b.line - a.line); });

      var dot_shift = right_shift;
      var x_width = 0;
      var last_line = null;
      var last_note = null;
      var prev_dotted_space = null;
      var half_shiftY = 0;

      for (i = 0; i < dot_list.length; ++i) {
        dot = dot_list[i].dot;
        note = dot_list[i].note;
        shift = dot_list[i].shift;
        var line = dot_list[i].line;

        // Reset the position of the dot every line.
        if (line != last_line || note != last_note) {
          dot_shift = shift;
        }

        if (!note.isRest() && line != last_line) {
          if (line % 1 == 0.5) {
            // note is on a space, so no dot shift
            half_shiftY = 0;
          } else if (!note.isRest()) {
            // note is on a line, so shift dot to space above the line
            half_shiftY = 0.5;
            if (last_note != null &&
                !last_note.isRest() && last_line - line == 0.5) {
              // previous note on a space, so shift dot to space below the line
              half_shiftY = -0.5;
            } else if (line + half_shiftY == prev_dotted_space) {
              // previous space is dotted, so shift dot to space below the line
               half_shiftY = -0.5;
            }
          }
        }

        // convert half_shiftY to a multiplier for dots.draw()
        dot.dot_shiftY += (-half_shiftY);
        prev_dotted_space = line + half_shiftY;

        dot.setXShift(dot_shift);
        dot_shift += dot.getWidth() + dot_spacing; // spacing
        x_width = (dot_shift > x_width) ? dot_shift : x_width;
        last_line = line;
        last_note = note;
      }

      this.state.right_shift += x_width;
      return this;
    },

    formatAccidentals: function() {
      var left_shift = this.state.left_shift;
      var accidentals = this.modifiers['accidentals'];
      var accidental_spacing = 2;

      if (!accidentals || accidentals.length === 0) return this;

      var acc_list = [];
      var hasStave = false;
      var prev_note = null;
      var shiftL = 0;

      var i, acc, props_tmp;
      for (i = 0; i < accidentals.length; ++i) {
        acc = accidentals[i];
        var note = acc.getNote();
        var stave = note.getStave();
        var props = note.getKeyProps()[acc.getIndex()];
        if (note != prev_note) {
           // Iterate through all notes to get the displaced pixels
           for (var n = 0; n < note.keys.length; ++n) {
              props_tmp = note.getKeyProps()[n];
              shiftL = (props_tmp.displaced ? note.getExtraLeftPx() : shiftL);
            }
            prev_note = note;
        }
        if (stave != null) {
          hasStave = true;
          var line_space = stave.options.spacing_between_lines_px;
          var y = stave.getYForLine(props.line);
          acc_list.push({ y: y, shift: shiftL, acc: acc, lineSpace: line_space });
        } else {
          acc_list.push({ line: props.line, shift: shiftL, acc: acc });
        }
      }

      // If stave assigned, format based on note y-position
      if (hasStave)
        return this.formatAccidentalsByY(acc_list);

      // Sort accidentals by line number.
      acc_list.sort(function(a, b) { return (b.line - a.line); });

      // If first note left shift in case it is displaced
      var acc_shift = acc_list[0].shift;
      var x_width = 0;
      var top_line = acc_list[0].line;
      for (i = 0; i < acc_list.length; ++i) {
        acc = acc_list[i].acc;
        var line = acc_list[i].line;
        var shift = acc_list[i].shift;

        // Once you hit three stave lines, you can reset the position of the
        // accidental.
        if (line < top_line - 3.0) {
          top_line = line;
          acc_shift = shift;
        }

        acc.setXShift(left_shift + acc_shift);
        acc_shift += acc.getWidth() + accidental_spacing; // spacing
        x_width = (acc_shift > x_width) ? acc_shift : x_width;
      }

      this.state.left_shift += x_width;
      return this;
    },

    formatAccidentalsByY: function(acc_list) {
      var left_shift = this.state.left_shift;
      var accidental_spacing = 2;

      // Sort accidentals by Y-position.
      acc_list.sort(function(a, b) { return (b.y - a.y); });

      // If first note is displaced, get the correct left shift
      var acc_shift = acc_list[0].shift;
      var x_width = 0;
      var top_y = acc_list[0].y;

      for (var i = 0; i < acc_list.length; ++i) {
        var acc = acc_list[i].acc;
        var y = acc_list[i].y;
        var shift = acc_list[i].shift;

        // Once you hit three stave lines, you can reset the position of the
        // accidental.
        if (top_y - y > 3 * acc_list[i].lineSpace) {
          top_y = y;
          acc_shift = shift;
        }

        acc.setXShift(acc_shift + left_shift);
        acc_shift += acc.getWidth() + accidental_spacing; // spacing
        x_width = (acc_shift > x_width) ? acc_shift : x_width;
      }

      this.state.left_shift += x_width;
      return this;
    },

    formatStrokes: function() {
      var left_shift = this.state.left_shift;
      var strokes = this.modifiers['strokes'];
      var stroke_spacing = 0;

      if (!strokes || strokes.length === 0) return this;

      var str_list = [];
      var i, str, shift;
      for (i = 0; i < strokes.length; ++i) {
        str = strokes[i];
        var note = str.getNote();
        var props;
        if (note instanceof Vex.Flow.StaveNote) {
          props = note.getKeyProps()[str.getIndex()];
          shift = (props.displaced ? note.getExtraLeftPx() : 0);
          str_list.push({ line: props.line, shift: shift, str: str });
        } else {
          props = note.getPositions()[str.getIndex()];
          str_list.push({ line: props.str, shift: 0, str: str });
        }
      }

      var str_shift = left_shift;
      var x_shift = 0;

      // There can only be one stroke .. if more than one, they overlay each other
      for (i = 0; i < str_list.length; ++i) {
        str = str_list[i].str;
        shift = str_list[i].shift;

        str.setXShift(str_shift + shift);
        x_shift = Math.max(str.getWidth() + stroke_spacing, x_shift);
      }

      this.state.left_shift += x_shift;
      return this;
    },

    formatStringNumbers: function() {
      var left_shift = this.state.left_shift;
      var right_shift = this.state.right_shift;
      var nums = this.modifiers['stringnumber'];
      var num_spacing = 1;

      if (!nums || nums.length === 0) return this;

      var nums_list = [];
      var prev_note = null;
      var shift_left = 0;
      var shift_right = 0;

      var i, num, note, pos, props_tmp;
      for (i = 0; i < nums.length; ++i) {
        num = nums[i];
        note = num.getNote();

        for (i = 0; i < nums.length; ++i) {
          num = nums[i];
          note = num.getNote();
          pos = num.getPosition();
          var props = note.getKeyProps()[num.getIndex()];

          if (note != prev_note) {
            for (var n = 0; n < note.keys.length; ++n) {
              props_tmp = note.getKeyProps()[n];
              if (left_shift === 0)
                shift_left = (props_tmp.displaced ? note.getExtraLeftPx() : shift_left);
              if (right_shift === 0)
                shift_right = (props_tmp.displaced ? note.getExtraRightPx() : shift_right);
            }
            prev_note = note;
          }

          nums_list.push({ line: props.line, pos: pos, shiftL: shift_left, shiftR: shift_right, note: note, num: num });
        }
      }

      // Sort string numbers by line number.
      nums_list.sort(function(a, b) { return (b.line - a.line); });

      var num_shiftL = 0;
      var num_shiftR = 0;
      var x_widthL = 0;
      var x_widthR = 0;
      var last_line = null;
      var last_note = null;
      for (i = 0; i < nums_list.length; ++i) {
        var num_shift = 0;
        note = nums_list[i].note;
        pos = nums_list[i].pos;
        num = nums_list[i].num;
        var line = nums_list[i].line;
        var shiftL = nums_list[i].shiftL;
        var shiftR = nums_list[i].shiftR;

        // Reset the position of the string number every line.
        if (line != last_line || note != last_note) {
          num_shiftL = left_shift + shiftL;
          num_shiftR = right_shift + shiftR;
        }

        var num_width = num.getWidth() + num_spacing;
        if (pos == Vex.Flow.Modifier.Position.LEFT) {
          num.setXShift(left_shift);
          num_shift = shift_left + num_width; // spacing
          x_widthL = (num_shift > x_widthL) ? num_shift : x_widthL;
        } else if (pos == Vex.Flow.Modifier.Position.RIGHT) {
          num.setXShift(num_shiftR);
          num_shift += num_width; // spacing
          x_widthR = (num_shift > x_widthR) ? num_shift : x_widthR;
        }
        last_line = line;
        last_note = note;
      }

      this.state.left_shift += x_widthL;
      this.state.right_shift += x_widthR;
      return this;
    },

    formatFretHandFingers: function() {
      var left_shift = this.state.left_shift;
      var right_shift = this.state.right_shift;
      var nums = this.modifiers['frethandfinger'];
      var num_spacing = 1;

      if (!nums || nums.length === 0) return this;

      var nums_list = [];
      var prev_note = null;
      var shift_left = 0;
      var shift_right = 0;

      var i, num, note, pos, props_tmp;
      for (i = 0; i < nums.length; ++i) {
        num = nums[i];
        note = num.getNote();
        pos = num.getPosition();
        var props = note.getKeyProps()[num.getIndex()];
        if (note != prev_note) {
          for (var n = 0; n < note.keys.length; ++n) {
            props_tmp = note.getKeyProps()[n];
            if (left_shift === 0)
              shift_left = (props_tmp.displaced ? note.getExtraLeftPx() : shift_left);
            if (right_shift === 0)
              shift_right = (props_tmp.displaced ? note.getExtraRightPx() : shift_right);
          }
          prev_note = note;
        }

        nums_list.push({ line: props.line, pos: pos, shiftL: shift_left, shiftR: shift_right, note: note, num: num });
      }

      // Sort fingernumbers by line number.
      nums_list.sort(function(a, b) { return (b.line - a.line); });

      var num_shiftL = 0;
      var num_shiftR = 0;
      var x_widthL = 0;
      var x_widthR = 0;
      var last_line = null;
      var last_note = null;

      for (i = 0; i < nums_list.length; ++i) {
        var num_shift = 0;
        note = nums_list[i].note;
        pos = nums_list[i].pos;
        num = nums_list[i].num;
        var line = nums_list[i].line;
        var shiftL = nums_list[i].shiftL;
        var shiftR = nums_list[i].shiftR;

        // Reset the position of the string number every line.
        if (line != last_line || note != last_note) {
          num_shiftL = left_shift + shiftL;
          num_shiftR = right_shift + shiftR;
        }

        var num_width = num.getWidth() + num_spacing;
        if (pos == Vex.Flow.Modifier.Position.LEFT) {
          num.setXShift(left_shift + num_shiftL);
          num_shift = left_shift + num_width; // spacing
          x_widthL = (num_shift > x_widthL) ? num_shift : x_widthL;
        } else if (pos == Vex.Flow.Modifier.Position.RIGHT) {
          num.setXShift(num_shiftR);
          num_shift = shift_right + num_width; // spacing
          x_widthR = (num_shift > x_widthR) ? num_shift : x_widthR;
        }
        last_line = line;
        last_note = note;
      }

      this.state.left_shift += x_widthL;
      this.state.right_shift += x_widthR;
      return this;
    },

    formatBends: function() {
      var bends = this.modifiers['bends'];
      if (!bends || bends.length === 0) return this;

      var last_width = 0;
      var text_line = this.state.text_line;

      // Format Bends
      for (var i = 0; i < bends.length; ++i) {
        var bend = bends[i];
        bend.setXShift(last_width);
        last_width = bend.getWidth();
        bend.setTextLine(text_line);
      }

      this.state.right_shift += last_width;
      this.state.text_line += 1;
      return this;
    },

    formatVibratos: function() {
      var vibratos = this.modifiers['vibratos'];
      if (!vibratos || vibratos.length === 0) return this;

      var text_line = this.state.text_line;
      var width = 0;
      var shift = this.state.right_shift - 7;

      // If there's a bend, drop the text line
      var bends = this.modifiers['bends'];
      if (bends && bends.length > 0) {
        text_line--;
      }

      // Format Vibratos
      for (var i = 0; i < vibratos.length; ++i) {
        var vibrato = vibratos[i];
        vibrato.setXShift(shift);
        vibrato.setTextLine(text_line);
        width += vibrato.getWidth();
        shift += width;
      }

      this.state.right_shift += width;
      this.state.text_line += 1;
      return this;
    },

    formatAnnotations: function() {
      var annotations = this.modifiers['annotations'];
      if (!annotations || annotations.length === 0) return this;

      var text_line = this.state.text_line;
      var max_width = 0;

      // Format Annotations
      var width;
      for (var i = 0; i < annotations.length; ++i) {
        var annotation = annotations[i];
        annotation.setTextLine(text_line);
        width = annotation.getWidth() > max_width ?
          annotation.getWidth() : max_width;
        text_line++;
      }

      this.state.left_shift += width / 2;
      this.state.right_shift += width / 2;
      // No need to update text_line because we leave lots of room on the same
      // line.
      return this;
    },

    formatArticulations: function() {
      var articulations = this.modifiers['articulations'];
      if (!articulations || articulations.length === 0) return this;

      var text_line = this.state.text_line;
      var max_width = 0;

      // Format Articulations
      var width;
      for (var i = 0; i < articulations.length; ++i) {
        var articulation = articulations[i];
        articulation.setTextLine(text_line);
        width = articulation.getWidth() > max_width ?
          articulation.getWidth() : max_width;

        var type = Vex.Flow.articulationCodes(articulation.type);
        if(type.between_lines)
          text_line += 1;
        else
          text_line += 1.5;
      }

      this.state.left_shift += width / 2;
      this.state.right_shift += width / 2;
      this.state.text_line = text_line;
      return this;
    },

    formatGraceNoteGroups: function(){
      var gracenote_groups = this.modifiers['gracenotegroups'];
      var gracenote_spacing = 4;

      if (!gracenote_groups || gracenote_groups.length === 0) return this;

      var group_list = [];
      var hasStave = false;
      var prev_note = null;
      var shiftL = 0;

      var i, gracenote_group, props_tmp;
      for (i = 0; i < gracenote_groups.length; ++i) {
        gracenote_group = gracenote_groups[i];
        var note = gracenote_group.getNote();
        var stave = note.getStave();
        if (note != prev_note) {
           // Iterate through all notes to get the displaced pixels
           for (var n = 0; n < note.keys.length; ++n) {
              props_tmp = note.getKeyProps()[n];
              shiftL = (props_tmp.displaced ? note.getExtraLeftPx() : shiftL);
            }
            prev_note = note;
        }
        if (stave != null) {
          hasStave = true;
          group_list.push({shift: shiftL, gracenote_group: gracenote_group});
        } else {
          group_list.push({shift: shiftL, gracenote_group: gracenote_group });
        }
      }

      // If first note left shift in case it is displaced
      var group_shift = group_list[0].shift;
      for (i = 0; i < group_list.length; ++i) {
        gracenote_group = group_list[i].gracenote_group;
        gracenote_group.preFormat();
        group_shift = gracenote_group.getWidth() + gracenote_spacing;
      }

      this.state.left_shift += group_shift;
      return this;
    },

    postFormatNotes: function() {
      var notes = this.modifiers['stavenotes'];

      if (!notes) return;

      notes.forEach(function(note) {
        note.postFormat();
      });

      return this;
    },

    preFormat: function() {
      if (this.preFormatted) return;

      // Format modifiers in the following order:
      this.formatNotes().
           formatDots().
           formatFretHandFingers().
           formatAccidentals().
           formatGraceNoteGroups().
           formatStrokes().
           formatStringNumbers().
           formatArticulations().
           formatAnnotations().
           formatBends().
           formatVibratos();

      // Update width of this modifier context
      this.width = this.state.left_shift + this.state.right_shift;
      this.preFormatted = true;
    },

    postFormat: function() {
      if (this.postFormatted) return;

      this.postFormatNotes();
      return this;
    }
  };

  return ModifierContext;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// This file implements accidentals as modifiers that can be attached to
// notes. Support is included for both western and microtonal accidentals.
//
// See `tests/accidental_tests.js` for usage examples.

Vex.Flow.Accidental = (function(){
  function Accidental(type) {
    if (arguments.length > 0) this.init(type);
  }

  // To enable logging for this class. Set `Vex.Flow.Accidental.DEBUG` to `true`.
  function L() { if (Accidental.DEBUG) Vex.L("Vex.Flow.Accidental", arguments); }

  var Modifier = Vex.Flow.Modifier;

  // ## Prototype Methods
  //
  // An `Accidental` inherits from `Modifier`, and is formatted within a
  // `ModifierContext`.
  Vex.Inherit(Accidental, Modifier, {
    // Create accidental. `type` can be a value from the
    // `Vex.Flow.accidentalCodes.accidentals` table in `tables.js`. For
    // example: `#`, `##`, `b`, `n`, etc.
    init: function(type) {
      Accidental.superclass.init.call(this);
      L("New accidental: ", type);

      this.note = null;
      // The `index` points to a specific note in a chord.
      this.index = null;
      this.type = type;
      this.position = Modifier.Position.LEFT;

      this.render_options = {
        // Font size for glyphs
        font_scale: 38,

        // Length of stroke across heads above or below the stave.
        stroke_px: 3
      };

      this.accidental = Vex.Flow.accidentalCodes(this.type);
      if (!this.accidental) throw new Vex.RERR("ArgumentError", "Unknown accidental type: " + type);

      // Cautionary accidentals have parentheses around them
      this.cautionary = false;
      this.paren_left = null;
      this.paren_right = null;

      // Initial width is set from table.
      this.setWidth(this.accidental.width);
    },

    // Return the modifier type. Used by the `ModifierContext` to calculate
    // layout.
    getCategory: function() { return "accidentals"; },

    // Attach this accidental to `note`, which must be a `StaveNote`.
    setNote: function(note){
      if (!note) throw new Vex.RERR("ArgumentError", "Bad note value: " + note);
      this.note = note;

      // Accidentals attached to grace notes are rendered smaller.
      if (this.note.getCategory() === 'gracenotes') {
        this.render_options.font_scale = 25;
        this.setWidth(this.accidental.gracenote_width);
      }
    },

    // If called, draws parenthesis around accidental.
    setAsCautionary: function() {
      this.cautionary = true;
      this.render_options.font_scale = 28;
      this.paren_left = Vex.Flow.accidentalCodes("{");
      this.paren_right = Vex.Flow.accidentalCodes("}");
      var width_adjust = (this.type == "##" || this.type == "bb") ? 6 : 4;

      // Make sure `width` accomodates for parentheses.
      this.setWidth(this.paren_left.width + this.accidental.width + this.paren_right.width - width_adjust);
      return this;
    },

    // Render accidental onto canvas.
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw accidental without a context.");
      if (!(this.note && (this.index != null))) throw new Vex.RERR("NoAttachedNote",
        "Can't draw accidental without a note and index.");

      // Figure out the start `x` and `y` coordinates for this note and index.
      var start = this.note.getModifierStartXY(this.position, this.index);
      var acc_x = (start.x + this.x_shift) - this.width;
      var acc_y = start.y + this.y_shift;
      L("Rendering: ", this.type, acc_x, acc_y);

      if (!this.cautionary) {
        // Render the accidental alone.
        Vex.Flow.renderGlyph(this.context, acc_x, acc_y,
                             this.render_options.font_scale, this.accidental.code);
      } else {
        // Render the accidental in parentheses.
        acc_x += 3;
        Vex.Flow.renderGlyph(this.context, acc_x, acc_y,
                             this.render_options.font_scale, this.paren_left.code);
        acc_x += 2;
        Vex.Flow.renderGlyph(this.context, acc_x, acc_y,
                             this.render_options.font_scale, this.accidental.code);
        acc_x += this.accidental.width - 2;
        if (this.type == "##" || this.type == "bb") acc_x -= 2;
        Vex.Flow.renderGlyph(this.context, acc_x, acc_y,
                             this.render_options.font_scale, this.paren_right.code);
      }
    }
  });

  return Accidental;
}());// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements dot modifiers for notes.

/**
 * @constructor
 */
Vex.Flow.Dot = (function() {
  function Dot() {
    this.init();
  }

  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(Dot, Modifier, {
    init: function() {
      Dot.superclass.init.call(this);

      this.note = null;
      this.index = null;
      this.position = Modifier.Position.RIGHT;

      this.radius = 2;
      this.setWidth(5);
      this.dot_shiftY = 0;
    },

    setNote: function(note){
      this.note = note;

      if (this.note.getCategory() === 'gracenotes') {
        this.radius *= 0.50;
        this.setWidth(3);
      }
    },

    getCategory: function() { return "dots"; },

    setDotShiftY: function(y) { this.dot_shiftY = y; return this; },

    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw dot without a context.");
      if (!(this.note && (this.index != null))) throw new Vex.RERR("NoAttachedNote",
        "Can't draw dot without a note and index.");

      var line_space = this.note.stave.options.spacing_between_lines_px;

      var start = this.note.getModifierStartXY(this.position, this.index);

      // Set the starting y coordinate to the base of the stem for TabNotes
      if (this.note.getCategory() === 'tabnotes') {
        start.y = this.note.getStemExtents().baseY;
      }

      var dot_x = (start.x + this.x_shift) + this.width - this.radius;
      var dot_y = start.y + this.y_shift + (this.dot_shiftY * line_space);
      var ctx = this.context;

      ctx.beginPath();
      ctx.arc(dot_x, dot_y, this.radius, 0, Math.PI * 2, false);
      ctx.fill();
    }
  });

  return Dot;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// This file implements the formatting and layout algorithms that are used
// to position notes in a voice. The algorithm can align multiple voices both
// within a stave, and across multiple staves.
//
// To do this, the formatter breaks up voices into a grid of rational-valued
// `ticks`, to which each note is assigned. Then, minimum widths are assigned
// to each tick based on the widths of the notes and modifiers in that tick. This
// establishes the smallest amount of space required for each tick.
//
// Finally, the formatter distributes the left over space proportionally to
// all the ticks, setting the `x` values of the notes in each tick.
//
// See `tests/formatter_tests.js` for usage examples. The helper functions included
// here (`FormatAndDraw`, `FormatAndDrawTab`) also serve as useful usage examples.

Vex.Flow.Formatter = (function() {
  function Formatter() {
    // Minimum width required to render all the notes in the voices.
    this.minTotalWidth = 0;

    // This is set to `true` after `minTotalWidth` is calculated.
    this.hasMinTotalWidth = false;

    // The suggested amount of space for each tick.
    this.pixelsPerTick = 0;

    // Total number of ticks in the voice.
    this.totalTicks = new Vex.Flow.Fraction(0, 1);

    // Arrays of tick and modifier contexts.
    this.tContexts = null;
    this.mContexts = null;
  }

  // To enable logging for this class. Set `Vex.Flow.Formatter.DEBUG` to `true`.
  function L() { if (Formatter.DEBUG) Vex.L("Vex.Flow.Formatter", arguments); }

  // ## Private Helpers
  //
  // Helper function to locate the next non-rest note(s).
  function lookAhead(notes, rest_line, i, compare) {
    // If no valid next note group, next_rest_line is same as current.
    var next_rest_line = rest_line;

    // Get the rest line for next valid non-rest note group.
    i++;
    while (i < notes.length) {
      if (!notes[i].isRest() && !notes[i].shouldIgnoreTicks()) {
        next_rest_line = notes[i].getLineForRest();
        break;
      }
      i++;
    }

    // Locate the mid point between two lines.
    if (compare && rest_line != next_rest_line) {
      var top = Vex.Max(rest_line, next_rest_line);
      var bot = Vex.Min(rest_line, next_rest_line);
      next_rest_line = Vex.MidLine(top, bot);
    }
    return next_rest_line;
  }

  // Take an array of `voices` and place aligned tickables in the same context. Returns
  // a mapping from `tick` to `context_type`, a list of `tick`s, and the resolution
  // multiplier.
  //
  // Params:
  // * `voices`: Array of `Voice` instances.
  // * `context_type`: A context class (e.g., `ModifierContext`, `TickContext`)
  // * `add_fn`: Function to add tickable to context.
  function createContexts(voices, context_type, add_fn) {
    if (!voices || !voices.length) throw new Vex.RERR("BadArgument",
        "No voices to format");

    // Initialize tick maps.
    var totalTicks = voices[0].getTotalTicks();
    var tickToContextMap = {};
    var tickList = [];

    var resolutionMultiplier = 1;

    // Find out highest common multiple of resolution multipliers.
    // The purpose of this is to find out a common denominator
    // for all fractional tick values in all tickables of all voices,
    // so that the values can be expanded and the numerator used
    // as an integer tick value.
    var i; // shared iterator
    var voice;
    for (i = 0; i < voices.length; ++i) {
      voice = voices[i];
      if (voice.getTotalTicks().value() != totalTicks.value()) {
        throw new Vex.RERR("TickMismatch",
            "Voices should have same time signature.");
      }

      if (voice.getMode() == Vex.Flow.Voice.Mode.STRICT && !voice.isComplete())
        throw new Vex.RERR("IncompleteVoice",
          "Voice does not have enough notes.");

      var lcm = Vex.Flow.Fraction.LCM(resolutionMultiplier,
          voice.getResolutionMultiplier());
      if (resolutionMultiplier < lcm) {
        resolutionMultiplier = lcm;
      }
    }

    // For each voice, extract notes and create a context for every
    // new tick that hasn't been seen before.
    for (i = 0; i < voices.length; ++i) {
      voice = voices[i];

      var tickables = voice.getTickables();

      // Use resolution multiplier as denominator to expand ticks
      // to suitable integer values, so that no additional expansion
      // of fractional tick values is needed.
      var ticksUsed = new Vex.Flow.Fraction(0, resolutionMultiplier);

      for (var j = 0; j < tickables.length; ++j) {
        var tickable = tickables[j];
        var integerTicks = ticksUsed.numerator;

        // If we have no tick context for this tick, create one.
        if (!tickToContextMap[integerTicks])
          tickToContextMap[integerTicks] = new context_type();

        // Add this tickable to the TickContext.
        add_fn(tickable, tickToContextMap[integerTicks]);

        // Maintain a sorted list of tick contexts.
        tickList.push(integerTicks);
        ticksUsed.add(tickable.getTicks());
      }
    }

    return {
      map: tickToContextMap,
      list: Vex.SortAndUnique(tickList, function(a, b) { return a - b; },
          function(a, b) { return a === b; } ),
      resolutionMultiplier: resolutionMultiplier
    };
  }


  // ## Static Methods
  //
  // Helper function to format and draw a single voice. Returns a bounding
  // box for the notation.
  //
  // Parameters:
  // * `ctx` - The rendering context
  // * `stave` - The stave to which to draw (`Stave` or `TabStave`)
  // * `notes` - Array of `Note` instances (`StaveNote`, `TextNote`, `TabNote`, etc.)
  // * `params` - One of below:
  //    * Setting `autobeam` only `(context, stave, notes, true)` or `(ctx, stave, notes, {autobeam: true})`
  //    * Setting `align_rests` a struct is needed `(context, stave, notes, {align_rests: true})`
  //    * Setting both a struct is needed `(context, stave, notes, {autobeam: true, align_rests: true})`
  //
  // `autobeam` automatically generates beams for the notes.
  // `align_rests` aligns rests with nearby notes.
  Formatter.FormatAndDraw = function(ctx, stave, notes, params) {
    var opts = {
      auto_beam: false,
      align_rests: false
    };

    if (typeof params == "object") {
      Vex.Merge(opts, params);
    } else if (typeof params == "boolean") {
      opts.auto_beam = params;
    }

    // Start by creating a voice and adding all the notes to it.
    var voice = new Vex.Flow.Voice(Vex.Flow.TIME4_4).
      setMode(Vex.Flow.Voice.Mode.SOFT);
    voice.addTickables(notes);

    // Then create beams, if requested.
    var beams = null;
    if (opts.auto_beam) {
      beams = Vex.Flow.Beam.applyAndGetBeams(voice);
    }

    // Instantiate a `Formatter` and format the notes.
    new Formatter().
      joinVoices([voice], {align_rests: opts.align_rests}).
      formatToStave([voice], stave, {align_rests: opts.align_rests});

    // Render the voice and beams to the stave.
    voice.setStave(stave);
    voice.draw(ctx, stave);
    if (beams != null) {
      for (var i=0; i<beams.length; ++i) {
        beams[i].setContext(ctx).draw();
      }
    }

    // Return the bounding box of the voice.
    return voice.getBoundingBox();
  };

  // Helper function to format and draw aligned tab and stave notes in two
  // separate staves.
  //
  // Parameters:
  // * `ctx` - The rendering context
  // * `tabstave` - A `TabStave` instance on which to render `TabNote`s.
  // * `stave` - A `Stave` instance on which to render `Note`s.
  // * `notes` - Array of `Note` instances for the stave (`StaveNote`, `BarNote`, etc.)
  // * `tabnotes` - Array of `Note` instances for the tab stave (`TabNote`, `BarNote`, etc.)
  // * `autobeam` - Automatically generate beams.
  // * `params` - A configuration object:
  //    * `autobeam` automatically generates beams for the notes.
  //    * `align_rests` aligns rests with nearby notes.
  Formatter.FormatAndDrawTab = function(ctx,
      tabstave, stave, tabnotes, notes, autobeam, params) {
    var opts = {
      auto_beam: autobeam,
      align_rests: false
    };

    if (typeof params == "object") {
      Vex.Merge(opts, params);
    } else if (typeof params == "boolean") {
      opts.auto_beam = params;
    }

    // Create a `4/4` voice for `notes`.
    var notevoice = new Vex.Flow.Voice(Vex.Flow.TIME4_4).
      setMode(Vex.Flow.Voice.Mode.SOFT);
    notevoice.addTickables(notes);

    // Create a `4/4` voice for `tabnotes`.
    var tabvoice = new Vex.Flow.Voice(Vex.Flow.TIME4_4).
      setMode(Vex.Flow.Voice.Mode.SOFT);
    tabvoice.addTickables(tabnotes);

    // Generate beams if requested.
    var beams = null;
    if (opts.auto_beam) {
      beams = Vex.Flow.Beam.applyAndGetBeams(notevoice);
    }


    // Instantiate a `Formatter` and align tab and stave notes.
    new Formatter().
      joinVoices([notevoice], {align_rests: opts.align_rests}).
      joinVoices([tabvoice]).
      formatToStave([notevoice,tabvoice], stave, {align_rests: opts.align_rests});

    // Render voices and beams to staves.
    notevoice.draw(ctx, stave);
    tabvoice.draw(ctx, tabstave);
    if (beams != null) {
      for (var i=0; i<beams.length; ++i) {
        beams[i].setContext(ctx).draw();
      }
    }

    // Draw a connector between tab and note staves.
    (new Vex.Flow.StaveConnector(stave, tabstave)).setContext(ctx).draw();
  };

  // Auto position rests based on previous/next note positions.
  //
  // Params:
  // * `notes`: An array of notes.
  // * `align_all_notes`: If set to false, only aligns non-beamed notes.
  // * `align_tuplets`: If set to false, ignores tuplets.
  Formatter.AlignRestsToNotes = function(notes, align_all_notes, align_tuplets) {
    for (var i = 0; i < notes.length; ++i) {
      if (notes[i] instanceof Vex.Flow.StaveNote && notes[i].isRest()) {
        var note = notes[i];

        if (note.tuplet && !align_tuplets) continue;

        // If activated rests not on default can be rendered as specified.
        var position = note.getGlyph().position.toUpperCase();
        if (position != "R/4" && position != "B/4") {
          continue;
        }

        if (align_all_notes || note.beam != null) {
          // Align rests with previous/next notes.
          var props = note.getKeyProps()[0];
          if (i === 0) {
            props.line = lookAhead(notes, props.line, i, false);
          } else if (i > 0 && i < notes.length) {
            // If previous note is a rest, use its line number.
            var rest_line;
            if (notes[i-1].isRest()) {
              rest_line = notes[i-1].getKeyProps()[0].line;
              props.line = rest_line;
            } else {
              rest_line = notes[i-1].getLineForRest();
              // Get the rest line for next valid non-rest note group.
              props.line = lookAhead(notes, rest_line, i, true);
            }
          }
        }
      }
    }

    return this;
  };

  // ## Prototype Methods
  Formatter.prototype = {
    // Find all the rests in each of the `voices` and align them
    // to neighboring notes. If `align_all_notes` is `false`, then only
    // align non-beamed notes.
    alignRests: function(voices, align_all_notes) {
      if (!voices || !voices.length) throw new Vex.RERR("BadArgument",
          "No voices to format rests");
      for (var i = 0; i < voices.length; i++) {
        new Formatter.AlignRestsToNotes(voices[i].tickables, align_all_notes);
      }
    },

    // Calculate the minimum width required to align and format `voices`.
    preCalculateMinTotalWidth: function(voices) {
      // Cache results.
      if (this.hasMinTotalWidth) return;

      // Create tick contexts if not already created.
      if (!this.tContexts) {
        if (!voices) {
          throw new Vex.RERR("BadArgument",
                             "'voices' required to run preCalculateMinTotalWidth");
        }
        this.createTickContexts(voices);
      }

      var contexts = this.tContexts;
      var contextList = contexts.list;
      var contextMap = contexts.map;

      this.minTotalWidth = 0;

      // Go through each tick context and calculate total width.
      for (var i = 0; i < contextList.length; ++i) {
        var context = contextMap[contextList[i]];

        // `preFormat` gets them to descend down to their tickables and modifier
        // contexts, and calculate their widths.
        context.preFormat();
        this.minTotalWidth += context.getWidth();
      }

      this.hasMinTotalWidth = true;

      return this.minTotalWidth;
    },

    // Get minimum width required to render all voices. Either `format` or
    // `preCalculateMinTotalWidth` must be called before this method.
    getMinTotalWidth: function() {
      if (!this.hasMinTotalWidth) {
        throw new Vex.RERR("NoMinTotalWidth",
            "Need to call 'preCalculateMinTotalWidth' or 'preFormat' before" +
            " calling 'getMinTotalWidth'");
      }

      return this.minTotalWidth;
    },

    // Create `ModifierContext`s for each tick in `voices`.
    createModifierContexts: function(voices) {
      var contexts = createContexts(voices,
          Vex.Flow.ModifierContext,
          function(tickable, context) {
            tickable.addToModifierContext(context);
          });
      this.mContexts = contexts;
      return contexts;
    },

    // Create `TickContext`s for each tick in `voices`. Also calculate the
    // total number of ticks in voices.
    createTickContexts: function(voices) {
      var contexts = createContexts(voices,
          Vex.Flow.TickContext,
          function(tickable, context) { context.addTickable(tickable); });

      this.totalTicks = voices[0].getTicksUsed().clone();
      this.tContexts = contexts;
      return contexts;
    },

    // This is the core formatter logic. Format voices and justify them
    // to `justifyWidth` pixels. `rendering_context` is required to justify elements
    // that can't retreive widths without a canvas. This method sets the `x` positions
    // of all the tickables/notes in the formatter.
    preFormat: function(justifyWidth, rendering_context, voices, stave) {
      // Initialize context maps.
      var contexts = this.tContexts;
      var contextList = contexts.list;
      var contextMap = contexts.map;

      // If voices and a stave were provided, set the Stave for each voice
      // and preFormat to apply Y values to the notes;
      if (voices && stave) {
        voices.forEach(function(voice) {
          voice.setStave(stave);
          voice.preFormat();
        });
      }

      // Figure out how many pixels to allocate per tick.
      if (!justifyWidth) {
        justifyWidth = 0;
        this.pixelsPerTick = 0;
      } else {
        this.pixelsPerTick = justifyWidth / (this.totalTicks.value() * contexts.resolutionMultiplier);
      }

      // Now distribute the ticks to each tick context, and assign them their
      // own X positions.
      var x = 0;
      var white_space = 0; // White space to right of previous note
      var tick_space = 0;  // Pixels from prev note x-pos to curent note x-pos
      var prev_tick = 0;
      var prev_width = 0;
      var lastMetrics = null;
      var initial_justify_width = justifyWidth;
      this.minTotalWidth = 0;

      var i, tick, context;

      // Pass 1: Give each note maximum width requested by context.
      for (i = 0; i < contextList.length; ++i) {
        tick = contextList[i];
        context = contextMap[tick];
        if (rendering_context) context.setContext(rendering_context);

        // Make sure that all tickables in this context have calculated their
        // space requirements.
        context.preFormat();

        var thisMetrics = context.getMetrics();
        var width = context.getWidth();
        this.minTotalWidth += width;
        var min_x = 0;
        var pixels_used = width;

        // Calculate space between last note and next note.
        tick_space = Math.min((tick - prev_tick) * this.pixelsPerTick, pixels_used);

        // Shift next note up `tick_space` pixels.
        var set_x = x + tick_space;

        // Calculate the minimum next note position to allow for right modifiers.
        if (lastMetrics != null) {
          min_x = x + prev_width - lastMetrics.extraLeftPx;
        }

        // Determine the space required for the previous tick.
        // The `shouldIgnoreTicks` bool is true for elements in the stave
        // that don't consume ticks (bar lines, key and time signatures, etc.)
        set_x = context.shouldIgnoreTicks() ?
            (min_x + context.getWidth()) : Math.max(set_x, min_x);

        if (context.shouldIgnoreTicks() && justifyWidth) {
            // This note stole room... recalculate with new justification width.
            justifyWidth -= context.getWidth();
            this.pixelsPerTick = justifyWidth /
              (this.totalTicks.value() * contexts.resolutionMultiplier);
        }

        // Determine pixels needed for left modifiers.
        var left_px = thisMetrics.extraLeftPx;

        // Determine white space to right of previous tick (from right modifiers.)
        if (lastMetrics != null) {
          white_space = (set_x - x) - (prev_width -
                                       lastMetrics.extraLeftPx);
        }

        // Deduct pixels from white space quota.
        if (i > 0) {
          if (white_space > 0) {
            if (white_space >= left_px) {
              // Have enough white space for left modifiers - no offset needed.
              left_px = 0;
            } else {
              // Decrease left modifier offset by amount of white space.
              left_px -= white_space;
            }
          }
        }

        // Adjust the tick x position with the left modifier offset.
        set_x += left_px;

        // Set the `x` value for the context, which sets the `x` value for all
        // tickables in this context.
        context.setX(set_x);
        context.setPixelsUsed(pixels_used);  // ??? Remove this if nothing breaks

        lastMetrics = thisMetrics;
        prev_width = width;
        prev_tick = tick;
        x = set_x;
      }

      this.hasMinTotalWidth = true;
      if (justifyWidth > 0) {
        // Pass 2: Take leftover width, and distribute it to proportionately to
        // all notes.
        var remaining_x = initial_justify_width - (x + prev_width);
        var leftover_pixels_per_tick = remaining_x / (this.totalTicks.value() * contexts.resolutionMultiplier);
        var accumulated_space = 0;
        prev_tick = 0;

        for (i = 0; i < contextList.length; ++i) {
          tick = contextList[i];
          context = contextMap[tick];
          tick_space = (tick - prev_tick) * leftover_pixels_per_tick;
          accumulated_space = accumulated_space + tick_space;
          context.setX(context.getX() + accumulated_space);
          prev_tick = tick;
        }
      }
    },

    // This is the top-level call for all formatting logic completed
    // after `x` *and* `y` values have been computed for the notes 
    // in the voices.
    postFormat: function() {
      // Postformat modifier contexts
      this.mContexts.list.forEach(function(mContext) {
        this.mContexts.map[mContext].postFormat();
      }, this);

      // Postformat tick contexts
      this.tContexts.list.forEach(function(tContext) {
        this.tContexts.map[tContext].postFormat();
      }, this);

      return this;
    },

    // Take all `voices` and create `ModifierContext`s out of them. This tells
    // the formatters that the voices belong on a single stave.
    joinVoices: function(voices) {
      this.createModifierContexts(voices);
      this.hasMinTotalWidth = false;
      return this;
    },

    // Align rests in voices, justify the contexts, and position the notes
    // so voices are aligned and ready to render onto the stave. This method
    // mutates the `x` positions of all tickables in `voices`.
    //
    // Voices are full justified to fit in `justifyWidth` pixels.
    //
    // Set `options.context` to the rendering context. Set `options.align_rests`
    // to true to enable rest alignment.
    format: function(voices, justifyWidth, options) {
      var opts = {
        align_rests: false,
        context: null,
        stave: null
      };

      Vex.Merge(opts, options);
      this.alignRests(voices, opts.align_rests);
      this.createTickContexts(voices);
      this.preFormat(justifyWidth, opts.context, voices, opts.stave);

      // Only postFormat if a stave was supplied for y value formatting
      if (opts.stave) this.postFormat();
      
      return this;
    },

    // This method is just like `format` except that the `justifyWidth` is inferred
    // from the `stave`.
    formatToStave: function(voices, stave, options) {
      var justifyWidth = stave.getNoteEndX() - stave.getNoteStartX() - 10;
      L("Formatting voices to width: ", justifyWidth);
      var opts = {context: stave.getContext()};
      Vex.Merge(opts, options);
      return this.format(voices, justifyWidth, opts);
    }
  };

  return Formatter;
}());// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements varies types of ties between contiguous notes. The
// ties include: regular ties, hammer ons, pull offs, and slides.

/**
 * Create a new tie from the specified notes. The notes must
 * be part of the same line, and have the same duration (in ticks).
 *
 * @constructor
 * @param {!Object} context The canvas context.
 * @param {!Object} notes The notes to tie up.
 * @param {!Object} Options
 */
Vex.Flow.StaveTie = (function() {
  function StaveTie(notes, text) {
    if (arguments.length > 0) this.init(notes, text);
  }

  StaveTie.prototype = {
    init: function(notes, text) {
      /**
       * Notes is a struct that has:
       *
       *  {
       *    first_note: Note,
       *    last_note: Note,
       *    first_indices: [n1, n2, n3],
       *    last_indices: [n1, n2, n3]
       *  }
       *
       **/
      this.notes = notes;
      this.context = null;
      this.text = text;

      this.render_options = {
          cp1: 8,      // Curve control point 1
          cp2: 12,      // Curve control point 2
          text_shift_x: 0,
          first_x_shift: 0,
          last_x_shift: 0,
          y_shift: 7,
          tie_spacing: 0,
          font: { family: "Arial", size: 10, style: "" }
        };

      this.font = this.render_options.font;
      this.setNotes(notes);
    },

    setContext: function(context) { this.context = context; return this; },
    setFont: function(font) { this.font = font; return this; },

    /**
     * Set the notes to attach this tie to.
     *
     * @param {!Object} notes The notes to tie up.
     */
    setNotes: function(notes) {
      if (!notes.first_note && !notes.last_note)
        throw new Vex.RuntimeError("BadArguments",
            "Tie needs to have either first_note or last_note set.");

      if (!notes.first_indices) notes.first_indices = [0];
      if (!notes.last_indices) notes.last_indices = [0];

      if (notes.first_indices.length != notes.last_indices.length)
        throw new Vex.RuntimeError("BadArguments", "Tied notes must have similar" +
          " index sizes");

      // Success. Lets grab 'em notes.
      this.first_note = notes.first_note;
      this.first_indices = notes.first_indices;
      this.last_note = notes.last_note;
      this.last_indices = notes.last_indices;
      return this;
    },

    /**
     * @return {boolean} Returns true if this is a partial bar.
     */
    isPartial: function() {
      return (!this.first_note || !this.last_note);
    },

    renderTie: function(params) {
      if (params.first_ys.length === 0 || params.last_ys.length === 0)
        throw new Vex.RERR("BadArguments", "No Y-values to render");

      var ctx = this.context;
      var cp1 = this.render_options.cp1;
      var cp2 = this.render_options.cp2;

      if (Math.abs(params.last_x_px - params.first_x_px) < 10) {
        cp1 = 2; cp2 = 8;
      }

      var first_x_shift = this.render_options.first_x_shift;
      var last_x_shift = this.render_options.last_x_shift;
      var y_shift = this.render_options.y_shift * params.direction;

      for (var i = 0; i < this.first_indices.length; ++i) {
        var cp_x = ((params.last_x_px + last_x_shift) +
                    (params.first_x_px + first_x_shift)) / 2;
        var first_y_px = params.first_ys[this.first_indices[i]] + y_shift;
        var last_y_px = params.last_ys[this.last_indices[i]] + y_shift;

        if (isNaN(first_y_px) || isNaN(last_y_px))
          throw new Vex.RERR("BadArguments", "Bad indices for tie rendering.");

        var top_cp_y = ((first_y_px + last_y_px) / 2) + (cp1 * params.direction);
        var bottom_cp_y = ((first_y_px + last_y_px) / 2) + (cp2 * params.direction);

        ctx.beginPath();
        ctx.moveTo(params.first_x_px + first_x_shift, first_y_px);
        ctx.quadraticCurveTo(cp_x, top_cp_y,
                             params.last_x_px + last_x_shift, last_y_px);
        ctx.quadraticCurveTo(cp_x, bottom_cp_y,
                             params.first_x_px + first_x_shift, first_y_px);

        ctx.closePath();
        ctx.fill();
      }
    },

    renderText: function(first_x_px, last_x_px) {
      if (!this.text) return;
      var center_x = (first_x_px + last_x_px) / 2;
      center_x -= this.context.measureText(this.text).width / 2;

      this.context.save();
      this.context.setFont(this.font.family, this.font.size, this.font.style);
      this.context.fillText(
          this.text, center_x + this.render_options.text_shift_x,
          (this.first_note || this.last_note).getStave().getYForTopText() - 1);
      this.context.restore();
    },

    draw: function() {
      if (!this.context)
        throw new Vex.RERR("NoContext", "No context to render tie.");
      var first_note = this.first_note;
      var last_note = this.last_note;
      var first_x_px, last_x_px, first_ys, last_ys, stem_direction;

      if (first_note) {
        first_x_px = first_note.getTieRightX() + this.render_options.tie_spacing;
        stem_direction = first_note.getStemDirection();
        first_ys = first_note.getYs();
      } else {
        first_x_px = last_note.getStave().getTieStartX();
        first_ys = last_note.getYs();
        this.first_indices = this.last_indices;
      }

      if (last_note) {
        last_x_px = last_note.getTieLeftX() + this.render_options.tie_spacing;
        stem_direction = last_note.getStemDirection();
        last_ys = last_note.getYs();
      } else {
        last_x_px = first_note.getStave().getTieEndX();
        last_ys = first_note.getYs();
        this.last_indices = this.first_indices;
      }

      this.renderTie({
        first_x_px: first_x_px,
        last_x_px: last_x_px,
        first_ys: first_ys,
        last_ys: last_ys,
        direction: stem_direction
      });

      this.renderText(first_x_px, last_x_px);
      return true;
    }
  };

  return StaveTie;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements varies types of ties between contiguous notes. The
// ties include: regular ties, hammer ons, pull offs, and slides.

/**
 * Create a new tie from the specified notes. The notes must
 * be part of the same line, and have the same duration (in ticks).
 *
 * @constructor
 * @param {!Object} context The canvas context.
 * @param {!Object} notes The notes to tie up.
 * @param {!Object} Options
 */
Vex.Flow.TabTie = (function() {
  function TabTie(notes, text) {
    if (arguments.length > 0) this.init(notes, text);
  }

  TabTie.createHammeron = function(notes) {
    return new TabTie(notes, "H");
  };

  TabTie.createPulloff = function(notes) {
    return new TabTie(notes, "P");
  };

  Vex.Inherit(TabTie, Vex.Flow.StaveTie, {
    init: function(notes, text) {
      /**
       * Notes is a struct that has:
       *
       *  {
       *    first_note: Note,
       *    last_note: Note,
       *    first_indices: [n1, n2, n3],
       *    last_indices: [n1, n2, n3]
       *  }
       *
       **/
      TabTie.superclass.init.call(this, notes, text);
      this.render_options.cp1 = 9;
      this.render_options.cp2 = 11;
      this.render_options.y_shift = 3;

      this.setNotes(notes);
    },

    draw: function() {
      if (!this.context)
        throw new Vex.RERR("NoContext", "No context to render tie.");
      var first_note = this.first_note;
      var last_note = this.last_note;
      var first_x_px, last_x_px, first_ys, last_ys;

      if (first_note) {
        first_x_px = first_note.getTieRightX() + this.render_options.tie_spacing;
        first_ys = first_note.getYs();
      } else {
        first_x_px = last_note.getStave().getTieStartX();
        first_ys = last_note.getYs();
        this.first_indices = this.last_indices;
      }

      if (last_note) {
        last_x_px = last_note.getTieLeftX() + this.render_options.tie_spacing;
        last_ys = last_note.getYs();
      } else {
        last_x_px = first_note.getStave().getTieEndX();
        last_ys = first_note.getYs();
        this.last_indices = this.first_indices;
      }

      this.renderTie({
        first_x_px: first_x_px,
        last_x_px: last_x_px,
        first_ys: first_ys,
        last_ys: last_ys,
        direction: -1           // Tab tie's are always face up.
      });

      this.renderText(first_x_px, last_x_px);
      return true;
    }
  });

  return TabTie;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements varies types of ties between contiguous notes. The
// ties include: regular ties, hammer ons, pull offs, and slides.

/**
 * Create a new tie from the specified notes. The notes must
 * be part of the same line, and have the same duration (in ticks).
 *
 * @constructor
 * @param {!Object} context The canvas context.
 * @param {!Object} notes The notes to tie up.
 * @param {!Object} Options
 */
Vex.Flow.TabSlide = (function() {
  function TabSlide(notes, direction) {
    if (arguments.length > 0) this.init(notes, direction);
  }

  TabSlide.SLIDE_UP = 1;
  TabSlide.SLIDE_DOWN = -1;

  TabSlide.createSlideUp = function(notes) {
    return new TabSlide(notes, TabSlide.SLIDE_UP);
  };

  TabSlide.createSlideDown = function(notes) {
    return new TabSlide(notes, TabSlide.SLIDE_DOWN);
  };

  Vex.Inherit(TabSlide, Vex.Flow.TabTie, {
    init: function(notes, direction) {
      /**
       * Notes is a struct that has:
       *
       *  {
       *    first_note: Note,
       *    last_note: Note,
       *    first_indices: [n1, n2, n3],
       *    last_indices: [n1, n2, n3]
       *  }
       *
       **/
      TabSlide.superclass.init.call(this, notes, "sl.");
      if (!direction) {
        var first_fret = notes.first_note.getPositions()[0].fret;
        var last_fret = notes.last_note.getPositions()[0].fret;

        direction = ((parseInt(first_fret, 10) > parseInt(last_fret, 10)) ?
          TabSlide.SLIDE_DOWN : TabSlide.SLIDE_UP);
      }

      this.slide_direction = direction;
      this.render_options.cp1 = 11;
      this.render_options.cp2 = 14;
      this.render_options.y_shift = 0.5;

      this.setFont({font: "Times", size: 10, style: "bold italic"});
      this.setNotes(notes);
    },

    renderTie: function(params) {
      if (params.first_ys.length === 0 || params.last_ys.length === 0)
        throw new Vex.RERR("BadArguments", "No Y-values to render");

      var ctx = this.context;
      var first_x_px = params.first_x_px;
      var first_ys = params.first_ys;
      var last_x_px = params.last_x_px;

      var direction = this.slide_direction;
      if (direction != TabSlide.SLIDE_UP &&
          direction != TabSlide.SLIDE_DOWN) {
        throw new Vex.RERR("BadSlide", "Invalid slide direction");
      }

      for (var i = 0; i < this.first_indices.length; ++i) {
        var slide_y = first_ys[this.first_indices[i]] +
          this.render_options.y_shift;

        if (isNaN(slide_y))
          throw new Vex.RERR("BadArguments", "Bad indices for slide rendering.");

        ctx.beginPath();
        ctx.moveTo(first_x_px, slide_y + (3 * direction));
        ctx.lineTo(last_x_px, slide_y - (3 * direction));
        ctx.closePath();
        ctx.stroke();
      }
    }
  });

  return TabSlide;
}());// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements bends.

/**
   @constructor

   @param text Text for bend ("Full", "Half", etc.) (DEPRECATED)
   @param release If true, render a release. (DEPRECATED)
   @param phrase If set, ignore "text" and "release", and use the more
                 sophisticated phrase specified.

   Example of a phrase:

     [{
       type: UP,
       text: "whole"
       width: 8;
     },
     {
       type: DOWN,
       text: "whole"
       width: 8;
     },
     {
       type: UP,
       text: "half"
       width: 8;
     },
     {
       type: UP,
       text: "whole"
       width: 8;
     },
     {
       type: DOWN,
       text: "1 1/2"
       width: 8;
     }]
 */
Vex.Flow.Bend = (function() {
  function Bend(text, release, phrase) {
    if (arguments.length > 0) this.init(text, release, phrase);
  }

  Bend.UP = 0;
  Bend.DOWN = 1;

  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(Bend, Modifier, {
    init: function(text, release, phrase) {
      var superclass = Vex.Flow.Bend.superclass;
      superclass.init.call(this);

      this.text = text;
      this.x_shift = 0;
      this.release = release || false;
      this.font = "10pt Arial";
      this.render_options = {
        line_width: 1.5,
        line_style: "#777777",
        bend_width: 8,
        release_width: 8
      };

      if (phrase) {
        this.phrase = phrase;
      } else {
        // Backward compatibility
        this.phrase = [{type: Bend.UP, text: this.text}];
        if (this.release) this.phrase.push({type: Bend.DOWN, text: ""});
      }

      this.updateWidth();
    },

    setXShift: function(value) {
      this.x_shift = value;
      this.updateWidth();
    },

    setFont: function(font) { this.font = font; return this; },

    getCategory: function() { return "bends"; },

    getText: function() { return this.text; },

    updateWidth: function() {
      var that = this;

      function measure_text(text) {
        var text_width;
        if (that.context) {
          text_width = that.context.measureText(text).width;
        } else {
          text_width = Vex.Flow.textWidth(text);
        }

        return text_width;
      }

      var total_width = 0;
      for (var i=0; i<this.phrase.length; ++i) {
        var bend = this.phrase[i];
        if ('width' in bend) {
          total_width += bend.width;
        } else {
          var additional_width = (bend.type == Bend.UP) ?
            this.render_options.bend_width : this.render_options.release_width;

          bend.width = Vex.Max(additional_width, measure_text(bend.text)) + 3;
          bend.draw_width = bend.width / 2;
          total_width += bend.width;
        }
      }

      this.setWidth(total_width + this.x_shift);
      return this;
    },

    draw: function() {
        if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw bend without a context.");
      if (!(this.note && (this.index != null))) throw new Vex.RERR("NoNoteForBend",
        "Can't draw bend without a note or index.");

      var start = this.note.getModifierStartXY(Modifier.Position.RIGHT,
          this.index);
      start.x += 3;
      start.y += 0.5;
      var x_shift = this.x_shift;

      var ctx = this.context;
      var bend_height = this.note.getStave().getYForTopText(this.text_line) + 3;
      var annotation_y = this.note.getStave().getYForTopText(this.text_line) - 1;
      var that = this;

      function renderBend(x, y, width, height) {
        var cp_x = x + width;
        var cp_y = y;

        ctx.save();
        ctx.beginPath();
        ctx.setLineWidth(that.render_options.line_width);
        ctx.setStrokeStyle(that.render_options.line_style);
        ctx.setFillStyle(that.render_options.line_style);
        ctx.moveTo(x, y);
        ctx.quadraticCurveTo(cp_x, cp_y, x + width, height);
        ctx.stroke();
        ctx.restore();
      }

      function renderRelease(x, y, width, height) {
        ctx.save();
        ctx.beginPath();
        ctx.setLineWidth(that.render_options.line_width);
        ctx.setStrokeStyle(that.render_options.line_style);
        ctx.setFillStyle(that.render_options.line_style);
        ctx.moveTo(x, height);
        ctx.quadraticCurveTo(
            x + width, height,
            x + width, y);
        ctx.stroke();
        ctx.restore();
      }

      function renderArrowHead(x, y, direction) {
        var width = 4;
        var dir = direction || 1;

        ctx.beginPath();
        ctx.moveTo(x, y);
        ctx.lineTo(x - width, y + width * dir);
        ctx.lineTo(x + width, y + width * dir);
        ctx.closePath();
        ctx.fill();
      }

      function renderText(x, text) {
        ctx.save();
        ctx.setRawFont(that.font);
        var render_x = x - (ctx.measureText(text).width / 2);
        ctx.fillText(text, render_x, annotation_y);
        ctx.restore();
      }

      var last_bend = null;
      var last_drawn_width = 0;
      for (var i=0; i<this.phrase.length; ++i) {
        var bend = this.phrase[i];
        if (i === 0) bend.draw_width += x_shift;

        last_drawn_width = bend.draw_width + (last_bend?last_bend.draw_width:0) - (i==1?x_shift:0);
        if (bend.type == Bend.UP) {
          if (last_bend && last_bend.type == Bend.UP) {
            renderArrowHead(start.x, bend_height);
          }

          renderBend(start.x, start.y, last_drawn_width, bend_height);
        }

        if (bend.type == Bend.DOWN) {
          if (last_bend && last_bend.type == Bend.UP) {
            renderRelease(start.x, start.y, last_drawn_width, bend_height);
          }

          if (last_bend && last_bend.type == Bend.DOWN) {
            renderArrowHead(start.x, start.y, -1);
            renderRelease(start.x, start.y, last_drawn_width, bend_height);
          }

          if (last_bend == null) {
            last_drawn_width = bend.draw_width;
            renderRelease(start.x, start.y, last_drawn_width, bend_height);
          }
        }

        renderText(start.x + last_drawn_width, bend.text);
        last_bend = bend;
        last_bend.x = start.x;

        start.x += last_drawn_width;
      }

      // Final arrowhead and text
      if (last_bend.type == Bend.UP) {
        renderArrowHead(last_bend.x + last_drawn_width, bend_height);
      } else if (last_bend.type == Bend.DOWN) {
        renderArrowHead(last_bend.x + last_drawn_width, start.y, -1);
      }
    }
  });

  return Bend;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements vibratos.

/**
 * @constructor
 */
Vex.Flow.Vibrato = (function() {
  function Vibrato() { this.init(); }

  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(Vibrato, Modifier, {
    init: function() {
      var superclass = Vex.Flow.Vibrato.superclass;
      superclass.init.call(this);

      this.harsh = false;
      this.position = Vex.Flow.Modifier.Position.RIGHT;
      this.render_options = {
        vibrato_width: 20,
        wave_height: 6,
        wave_width: 4,
        wave_girth: 2
      };

      this.setVibratoWidth(this.render_options.vibrato_width);
    },

    getCategory: function() { return "vibratos"; },
    setHarsh: function(harsh) { this.harsh = harsh; return this; },
    setVibratoWidth: function(width) {
      this.vibrato_width = width;
      this.setWidth(this.vibrato_width);
      return this;
    },

    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw vibrato without a context.");
      if (!this.note) throw new Vex.RERR("NoNoteForVibrato",
        "Can't draw vibrato without an attached note.");

      var start = this.note.getModifierStartXY(Vex.Flow.Modifier.Position.RIGHT,
          this.index);

      var ctx = this.context;
      var that = this;
      var vibrato_width = this.vibrato_width;

      function renderVibrato(x, y) {
        var wave_width = that.render_options.wave_width;
        var wave_girth = that.render_options.wave_girth;
        var wave_height = that.render_options.wave_height;
        var num_waves = vibrato_width / wave_width;

        ctx.beginPath();

        var i;
        if (that.harsh) {
          ctx.moveTo(x, y + wave_girth + 1);
          for (i = 0; i < num_waves / 2; ++i) {
            ctx.lineTo(x + wave_width, y - (wave_height / 2));
            x += wave_width;
            ctx.lineTo(x + wave_width, y + (wave_height / 2));
            x += wave_width;
          }
          for (i = 0; i < num_waves / 2; ++i) {
            ctx.lineTo(x - wave_width, (y - (wave_height / 2)) + wave_girth + 1);
            x -= wave_width;
            ctx.lineTo(x - wave_width, (y + (wave_height / 2)) + wave_girth + 1);
            x -= wave_width;
          }
          ctx.fill();
        } else {
          ctx.moveTo(x, y + wave_girth);
          for (i = 0; i < num_waves / 2; ++i) {
            ctx.quadraticCurveTo(x + (wave_width / 2), y - (wave_height / 2),
              x + wave_width, y);
            x += wave_width;
            ctx.quadraticCurveTo(x + (wave_width / 2), y + (wave_height / 2),
              x + wave_width, y);
            x += wave_width;
          }

          for (i = 0; i < num_waves / 2; ++i) {
            ctx.quadraticCurveTo(
                x - (wave_width / 2),
                (y + (wave_height / 2)) + wave_girth,
                x - wave_width, y + wave_girth);
            x -= wave_width;
            ctx.quadraticCurveTo(
                x - (wave_width / 2),
                (y - (wave_height / 2)) + wave_girth,
                x - wave_width, y + wave_girth);
            x -= wave_width;
          }
          ctx.fill();
        }
      }

      var vx = start.x + this.x_shift;
      var vy = this.note.getYForTopText(this.text_line) + 2;

      renderVibrato(vx, vy);
    }
  });

  return Vibrato;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// This file implements text annotations as modifiers that can be attached to
// notes.
//
// See `tests/annotation_tests.js` for usage examples.

Vex.Flow.Annotation = (function() {
  function Annotation(text) {
    if (arguments.length > 0) this.init(text);
  }

  // To enable logging for this class. Set `Vex.Flow.Annotation.DEBUG` to `true`.
  function L() { if (Annotation.DEBUG) Vex.L("Vex.Flow.Annotation", arguments); }

  // Text annotations can be positioned and justified relative to the note.
  Annotation.Justify = {
    LEFT: 1,
    CENTER: 2,
    RIGHT: 3,
    CENTER_STEM: 4
  };

  Annotation.VerticalJustify = {
    TOP: 1,
    CENTER: 2,
    BOTTOM: 3,
    CENTER_STEM: 4
  };

  // ## Prototype Methods
  //
  // Annotations inherit from `Modifier` and is positioned correctly when
  // in a `ModifierContext`.
  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(Annotation, Modifier, {
    // Create a new `Annotation` with the string `text`.
    init: function(text) {
      Annotation.superclass.init.call(this);

      this.note = null;
      this.index = null;
      this.text_line = 0;
      this.text = text;
      this.justification = Annotation.Justify.CENTER;
      this.vert_justification = Annotation.VerticalJustify.TOP;
      this.font = {
        family: "Arial",
        size: 10,
        weight: ""
      };

      // The default width is calculated from the text.
      this.setWidth(Vex.Flow.textWidth(text));
    },

    // Return the modifier type. Used by the `ModifierContext` to calculate
    // layout.
    getCategory: function() { return "annotations"; },

    // Set the vertical position of the text relative to the stave.
    setTextLine: function(line) { this.text_line = line; return this; },

    // Set font family, size, and weight. E.g., `Arial`, `10pt`, `Bold`.
    setFont: function(family, size, weight) {
      this.font = { family: family, size: size, weight: weight };
      return this;
    },

    // Set vertical position of text (above or below stave). `just` must be
    // a value in `Annotation.VerticalJustify`.
    setVerticalJustification: function(just) {
      this.vert_justification = just;
      return this;
    },

    // Get and set horizontal justification. `justification` is a value in
    // `Annotation.Justify`.
    getJustification: function() { return this.justification; },
    setJustification: function(justification) {
      this.justification = justification; return this; },

    // Render text beside the note.
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw text annotation without a context.");
      if (!this.note) throw new Vex.RERR("NoNoteForAnnotation",
        "Can't draw text annotation without an attached note.");

      var start = this.note.getModifierStartXY(Modifier.Position.ABOVE,
          this.index);

      // We're changing context parameters. Save current state.
      this.context.save();
      this.context.setFont(this.font.family, this.font.size, this.font.weight);
      var text_width = this.context.measureText(this.text).width;

      // Estimate text height to be the same as the width of an 'm'.
      //
      // This is a hack to work around the inability to measure text height
      // in HTML5 Canvas (and SVG).
      var text_height = this.context.measureText("m").width;
      var x, y;

      if (this.justification == Annotation.Justify.LEFT) {
        x = start.x;
      } else if (this.justification == Annotation.Justify.RIGHT) {
        x = start.x - text_width;
      } else if (this.justification == Annotation.Justify.CENTER) {
        x = start.x - text_width / 2;
      } else /* CENTER_STEM */ {
        x = this.note.getStemX() - text_width / 2;
      }

      var stem_ext, spacing;
      var has_stem = this.note.hasStem();
      var stave = this.note.getStave();

      // The position of the text varies based on whether or not the note
      // has a stem.
      if (has_stem) {
        stem_ext = this.note.getStem().getExtents();
        spacing = stave.getSpacingBetweenLines();
      }

      if (this.vert_justification == Annotation.VerticalJustify.BOTTOM) {
        y = stave.getYForBottomText(this.text_line);
        if (has_stem) {
          var stem_base = (this.note.getStemDirection() === 1 ? stem_ext.baseY : stem_ext.topY);
          y = Math.max(y, stem_base + (spacing * (this.text_line + 2)));
        }
      } else if (this.vert_justification ==
                 Annotation.VerticalJustify.CENTER) {
        var yt = this.note.getYForTopText(this.text_line) - 1;
        var yb = stave.getYForBottomText(this.text_line);
        y = yt + ( yb - yt ) / 2 + text_height / 2;
      } else if (this.vert_justification ==
                 Annotation.VerticalJustify.TOP) {
        y = Math.min(stave.getYForTopText(this.text_line), this.note.getYs()[0] - 10);
        if (has_stem) {
          y = Math.min(y, (stem_ext.topY - 5) - (spacing * this.text_line));
        }
      } else /* CENTER_STEM */{
        var extents = this.note.getStemExtents();
        y = extents.topY + (extents.baseY - extents.topY) / 2 +
          text_height / 2;
      }

      L("Rendering annotation: ", this.text, x, y);
      this.context.fillText(this.text, x, y);
      this.context.restore();
    }
  });

  return Annotation;
}());// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
// Author: Larry Kuhns.
//
// ## Description
//
// This file implements articulations and accents as modifiers that can be
// attached to notes. The complete list of articulations is available in
// `tables.js` under `Vex.Flow.articulationCodes`.
//
// See `tests/articulation_tests.js` for usage examples.

Vex.Flow.Articulation = (function() {
  function Articulation(type) {
    if (arguments.length > 0) this.init(type);
  }

  // To enable logging for this class. Set `Vex.Flow.Articulation.DEBUG` to `true`.
  function L() { if (Articulation.DEBUG) Vex.L("Vex.Flow.Articulation", arguments); }

  var Modifier = Vex.Flow.Modifier;

  // ## Prototype Methods
  Vex.Inherit(Articulation, Modifier, {
    // Create a new articulation of type `type`, which is an entry in
    // `Vex.Flow.articulationCodes` in `tables.js`.
    init: function(type) {
      Articulation.superclass.init.call(this);

      this.note = null;
      this.index = null;
      this.type = type;
      this.position = Modifier.Position.BELOW;

      this.render_options = {
        font_scale: 38
      };

      this.articulation = Vex.Flow.articulationCodes(this.type);
      if (!this.articulation) throw new Vex.RERR("ArgumentError",
         "Articulation not found: '" + this.type + "'");

      // Default width comes from articulation table.
      this.setWidth(this.articulation.width);
    },

    // Get modifier category for `ModifierContext`.
    getCategory: function() { return "articulations"; },

    // Render articulation in position next to note.
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw Articulation without a context.");
      if (!(this.note && (this.index !== null))) throw new Vex.RERR("NoAttachedNote",
        "Can't draw Articulation without a note and index.");

      var stem_direction = this.note.getStemDirection();
      var stave = this.note.getStave();

      var is_on_head = (this.position === Modifier.Position.ABOVE &&
                        stem_direction === Vex.Flow.StaveNote.STEM_DOWN) ||
                       (this.position === Modifier.Position.BELOW &&
                        stem_direction === Vex.Flow.StaveNote.STEM_UP);

      var needsLineAdjustment = function(articulation, note_line, line_spacing) {
        var offset_direction = (articulation.position === Modifier.Position.ABOVE) ? 1 : -1;
        var duration = articulation.getNote().getDuration();

        if(!is_on_head && duration !== "w" && duration !== "1"){
          // Add stem length, inless it's on a whole note
          note_line += offset_direction * 3.5;
        }

        var articulation_line = note_line + (offset_direction * line_spacing);

        if(articulation_line >= 1 &&
           articulation_line <= 5 &&
           articulation_line % 1 === 0){
          return true;
        }

        return false;
      };

      // Articulations are centered over/under the note head.
      var start = this.note.getModifierStartXY(this.position, this.index);
      var glyph_y = start.y;
      var shiftY = 0;
      var line_spacing = 1;
      var spacing = stave.getSpacingBetweenLines();
      var is_tabnote = this.note.getCategory() === 'tabnotes';
      var stem_ext = this.note.getStem().getExtents();

      var top = stem_ext.topY;
      var bottom = stem_ext.baseY;

      if (stem_direction === Vex.Flow.StaveNote.STEM_DOWN) {
        top = stem_ext.baseY;
        bottom = stem_ext.topY;
      }

      // TabNotes don't have stems attached to them. Tab stems are rendered
      // outside the stave.
      if (is_tabnote) {
        if (this.note.hasStem()){
          if (stem_direction === Vex.Flow.StaveNote.STEM_UP) {
            bottom = stave.getYForBottomText(this.text_line - 2);
          } else if (stem_direction === Vex.Flow.StaveNote.STEM_DOWN ) {
            top = stave.getYForTopText(this.text_line - 1.5);
          }
        } else { // Without a stem
          top = stave.getYForTopText(this.text_line - 1);
          bottom = stave.getYForBottomText(this.text_line - 2);
        }
      }

      var is_above = (this.position === Modifier.Position.ABOVE) ? true : false;
      var note_line = this.note.getLineNumber(is_above);

      // Beamed stems are longer than quarter note stems.
      if (!is_on_head && this.note.beam) line_spacing += 0.5;

      // If articulation will overlap a line, reposition it.
      if (needsLineAdjustment(this, note_line, line_spacing)) line_spacing += 0.5;

      var glyph_y_between_lines;
      if (this.position === Modifier.Position.ABOVE) {
        shiftY = this.articulation.shift_up;
        glyph_y_between_lines = (top - 7) - (spacing * (this.text_line + line_spacing));

        if (this.articulation.between_lines)
          glyph_y = glyph_y_between_lines;
        else
          glyph_y = Math.min(stave.getYForTopText(this.text_line) - 3, glyph_y_between_lines);
      } else {
        shiftY = this.articulation.shift_down - 10;

        glyph_y_between_lines = bottom + 10 + spacing * (this.text_line + line_spacing);
        if (this.articulation.between_lines)
          glyph_y = glyph_y_between_lines;
        else
          glyph_y = Math.max(stave.getYForBottomText(this.text_line), glyph_y_between_lines);
      }

      var glyph_x = start.x + this.articulation.shift_right;
      glyph_y += shiftY + this.y_shift;

      L("Rendering articulation: ", this.articulation, glyph_x, glyph_y);
      Vex.Flow.renderGlyph(this.context, glyph_x, glyph_y,
                           this.render_options.font_scale, this.articulation.code);
    }
  });

  return Articulation;
}());// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements varies types of tunings for tablature.

/**
 * @constructor
 */
Vex.Flow.Tuning = (function() {
  function Tuning(tuningString) {
    this.init(tuningString);
  }

  Tuning.names = {
    "standard": "E/5,B/4,G/4,D/4,A/3,E/3",
    "dagdad": "D/5,A/4,G/4,D/4,A/3,D/3",
    "dropd": "E/5,B/4,G/4,D/4,A/3,D/3",
    "eb": "Eb/5,Bb/4,Gb/4,Db/4,Ab/3,Db/3"
  };

  Tuning.prototype = {
    init: function(tuningString) {
      // Default to standard tuning.
      this.setTuning(tuningString || "E/5,B/4,G/4,D/4,A/3,E/3,B/2,E/2");
    },

    noteToInteger: function(noteString) {
      return Vex.Flow.keyProperties(noteString).int_value;
    },

    setTuning: function(noteString) {
      if (Vex.Flow.Tuning.names[noteString])
        noteString = Vex.Flow.Tuning.names[noteString];

      this.tuningString = noteString;
      this.tuningValues = [];
      this.numStrings = 0;

      var keys = noteString.split(/\s*,\s*/);
      if (keys.length === 0)
        throw new Vex.RERR("BadArguments", "Invalid tuning string: " + noteString);

      this.numStrings = keys.length;
      for (var i = 0; i < this.numStrings; ++i) {
        this.tuningValues[i] = this.noteToInteger(keys[i]);
      }
    },

    getValueForString: function(stringNum) {
      var s = parseInt(stringNum, 10);
      if (s < 1 || s > this.numStrings)
        throw new Vex.RERR("BadArguments", "String number must be between 1 and " +
            this.numStrings + ": " + stringNum);

      return this.tuningValues[s - 1];
    },

    getValueForFret: function(fretNum, stringNum) {
      var stringValue = this.getValueForString(stringNum);
      var f = parseInt(fretNum, 10);

      if (f < 0) {
        throw new Vex.RERR("BadArguments", "Fret number must be 0 or higher: " +
            fretNum);
      }

      return stringValue + f;
    },

    getNoteForFret: function(fretNum, stringNum) {
      var noteValue = this.getValueForFret(fretNum, stringNum);

      var octave = Math.floor(noteValue / 12);
      var value = noteValue % 12;

      return Vex.Flow.integerToNote(value) + "/" + octave;
    }
  };

  return Tuning;
}());
// VexFlow - Music Engraving for HTML5
//
// A base class for stave modifiers (e.g. clefs, key signatures)
//


/**
 * @constructor
 */
Vex.Flow.StaveModifier = (function() {
  function StaveModifier() {
    this.init();
  }

  StaveModifier.prototype = {
    init: function() {
      this.padding = 10;
    },

    getCategory: function() {return "";},
    makeSpacer: function(padding) {
      return {
        getContext: function() {return true;},
        setStave: function() {},
        renderToStave: function() {},
        getMetrics: function() {
          return {width: padding};
        }
      };
    },

    placeGlyphOnLine: function(glyph, stave, line) {
      glyph.setYShift(stave.getYForLine(line) - stave.getYForGlyphs());
    },

    setPadding: function(padding) {
      this.padding = padding;
    },

    addToStave: function(stave, firstGlyph) {
      if (!firstGlyph) {
        stave.addGlyph(this.makeSpacer(this.padding));
      }

      this.addModifier(stave);
      return this;
    },

    addToStaveEnd: function(stave, firstGlyph) {
      if (!firstGlyph) {
        stave.addEndGlyph(this.makeSpacer(this.padding));
      }
      else {
        stave.addEndGlyph(this.makeSpacer(2));
      }

      this.addEndModifier(stave);
      return this;
    },

    addModifier: function() {
      throw new Vex.RERR("MethodNotImplemented",
          "addModifier() not implemented for this stave modifier.");
    },

    addEndModifier: function() {
      throw new Vex.RERR("MethodNotImplemented",
          "addEndModifier() not implemented for this stave modifier.");
    }
  };

  return StaveModifier;
}());

// Vex Flow Notation
// Implements key signatures
//
// Requires vex.js.

/**
 * @constructor
 */
Vex.Flow.KeySignature = (function() {
  function KeySignature(keySpec) {
    if (arguments.length > 0) this.init(keySpec);
  }

  Vex.Inherit(KeySignature, Vex.Flow.StaveModifier, {
    init: function(key_spec) {
      KeySignature.superclass.init();

      this.glyphFontScale = 38; // TODO(0xFE): Should this match StaveNote?
      this.accList = Vex.Flow.keySignature(key_spec);
    },

    addAccToStave: function(stave, acc) {
      var glyph = new Vex.Flow.Glyph(acc.glyphCode, this.glyphFontScale);
      this.placeGlyphOnLine(glyph, stave, acc.line);
      stave.addGlyph(glyph);
    },

    addModifier: function(stave) {
      this.convertAccLines(stave.clef, this.accList[0].glyphCode);
      for (var i = 0; i < this.accList.length; ++i) {
        this.addAccToStave(stave, this.accList[i]);
      }
    },

    addToStave: function(stave, firstGlyph) {
      if (this.accList.length === 0)
        return this;

      if (!firstGlyph) {
        stave.addGlyph(this.makeSpacer(this.padding));
      }

      this.addModifier(stave);
      return this;
    },

    convertAccLines: function(clef, code) {
      var offset = 0.0; // if clef === "treble"
      var tenorSharps;
      var isTenorSharps = ((clef === "tenor") && (code === "v18")) ? true : false;

      switch (clef) {
        case "bass":
          offset = 1;
          break;
        case "alto":
          offset = 0.5;
          break;
        case "tenor":
          if (!isTenorSharps) {
            offset = -0.5;
          }
          break;
      }

      // Special-case for TenorSharps
      var i;
      if (isTenorSharps) {
        tenorSharps = [3, 1, 2.5, 0.5, 2, 0, 1.5];
        for (i = 0; i < this.accList.length; ++i) {
          this.accList[i].line = tenorSharps[i];
        }
      }
      else {
        if (clef != "treble") {
          for (i = 0; i < this.accList.length; ++i) {
            this.accList[i].line += offset;
          }
        }
      }
    }
  });

  return KeySignature;
}());// Vex Flow Notation
// Implements time signatures glyphs for staffs
// See tables.js for the internal time signatures
// representation
//

/**
 * @param {string} timeSpec time signature, i.e. "4/4"
 * @param {number} [customPadding] custom padding when using multi-stave/multi-instrument setting
 * to align key/time signature (in pixels), optional
 * @constructor
 */
Vex.Flow.TimeSignature = (function() {
  function TimeSignature(timeSpec, customPadding) {
    if (arguments.length > 0) this.init(timeSpec, customPadding);
  }

  TimeSignature.glyphs = {
    "C": {
      code: "v41",
      point: 40,
      line: 2
    },
    "C|": {
      code: "vb6",
      point: 40,
      line: 2
    }
  };

  Vex.Inherit(TimeSignature, Vex.Flow.StaveModifier, {
    init: function(timeSpec, customPadding) {
      TimeSignature.superclass.init();
       var padding = customPadding || 15;

      this.setPadding(padding);
      this.point = 40;
      this.topLine = 2;
      this.bottomLine = 4;
      this.timeSig = this.parseTimeSpec(timeSpec);
    },

    parseTimeSpec: function(timeSpec) {
      if (timeSpec == "C" || timeSpec == "C|") {
        var glyphInfo = TimeSignature.glyphs[timeSpec];
        return {num: false, line: glyphInfo.line,
          glyph: new Vex.Flow.Glyph(glyphInfo.code, glyphInfo.point)};
      }

      var topNums = [];
      var i, c;
      for (i = 0; i < timeSpec.length; ++i) {
        c = timeSpec.charAt(i);
        if (c == "/") {
          break;
        }
        else if (/[0-9]/.test(c)) {
          topNums.push(c);
        }
        else {
          throw new Vex.RERR("BadTimeSignature",
              "Invalid time spec: " + timeSpec);
        }
      }

      if (i === 0) {
        throw new Vex.RERR("BadTimeSignature",
              "Invalid time spec: " + timeSpec);
      }

      // skip the "/"
      ++i;

      if (i == timeSpec.length) {
        throw new Vex.RERR("BadTimeSignature",
              "Invalid time spec: " + timeSpec);
      }


      var botNums = [];
      for (; i < timeSpec.length; ++i) {
        c = timeSpec.charAt(i);
        if (/[0-9]/.test(c)) {
          botNums.push(c);
        }
        else {
          throw new Vex.RERR("BadTimeSignature",
              "Invalid time spec: " + timeSpec);
        }
      }


      return {num: true, glyph: this.makeTimeSignatureGlyph(topNums, botNums)};
    },

    makeTimeSignatureGlyph: function(topNums, botNums) {
      var glyph = new Vex.Flow.Glyph("v0", this.point);
      glyph["topGlyphs"] = [];
      glyph["botGlyphs"] = [];

      var topWidth = 0;
      var i, num;
      for (i = 0; i < topNums.length; ++i) {
        num = topNums[i];
        var topGlyph = new Vex.Flow.Glyph("v" + num, this.point);

        glyph.topGlyphs.push(topGlyph);
        topWidth += topGlyph.getMetrics().width;
      }

      var botWidth = 0;
      for (i = 0; i < botNums.length; ++i) {
        num = botNums[i];
        var botGlyph = new Vex.Flow.Glyph("v" + num, this.point);

        glyph.botGlyphs.push(botGlyph);
        botWidth += botGlyph.getMetrics().width;
      }

      var width = (topWidth > botWidth ? topWidth : botWidth);
      var xMin = glyph.getMetrics().x_min;

      glyph.getMetrics = function() {
        return {
          x_min: xMin,
          x_max: xMin + width,
          width: width
        };
      };

      var topStartX = (width - topWidth) / 2.0;
      var botStartX = (width - botWidth) / 2.0;

      var that = this;
      glyph.renderToStave = function(x) {
        var start_x = x + topStartX;
        var i, g;
        for (i = 0; i < this.topGlyphs.length; ++i) {
          g = this.topGlyphs[i];
          Vex.Flow.Glyph.renderOutline(this.context, g.metrics.outline,
              g.scale, start_x + g.x_shift, this.stave.getYForLine(that.topLine) + 1);
          start_x += g.getMetrics().width;
        }

        start_x = x + botStartX;
        for (i = 0; i < this.botGlyphs.length; ++i) {
          g = this.botGlyphs[i];
          that.placeGlyphOnLine(g, this.stave, g.line);
          Vex.Flow.Glyph.renderOutline(this.context, g.metrics.outline,
              g.scale, start_x + g.x_shift, this.stave.getYForLine(that.bottomLine) + 1);
          start_x += g.getMetrics().width;
        }
      };

      return glyph;
    },

    getTimeSig: function() {
      return this.timeSig;
    },

    addModifier: function(stave) {
      if (!this.timeSig.num) {
        this.placeGlyphOnLine(this.timeSig.glyph, stave, this.timeSig.line);
      }
      stave.addGlyph(this.timeSig.glyph);
    },

    addEndModifier: function(stave) {
      if (!this.timeSig.num) {
        this.placeGlyphOnLine(this.timeSig.glyph, stave, this.timeSig.line);
      }
      stave.addEndGlyph(this.timeSig.glyph);
    }
  });

  return TimeSignature;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna Cheppudira 2013.
// Co-author: Benjamin W. Bohl
//
// ## Description
//
// This file implements various types of clefs that can be rendered on a stave.
//
// See `tests/clef_tests.js` for usage examples.

Vex.Flow.Clef = (function() {
  function Clef(clef) {
    if (arguments.length > 0) this.init(clef);
  }

  // To enable logging for this class, set `Vex.Flow.Clef.DEBUG` to `true`.
  function L() { if (Vex.Flow.Clef.DEBUG) Vex.L("Vex.Flow.Clef", arguments); }

  // Every clef name is associated with a glyph code from the font file, a
  // point size, and a default stave line number.
  Clef.types = {
    "treble": {
      code: "v83",
      point: 40,
      line: 3
    },
    "bass": {
      code: "v79",
      point: 40,
      line: 1
    },
    "alto": {
      code: "vad",
      point: 40,
      line: 2
    },
    "tenor": {
      code: "vad",
      point: 40,
      line: 1
    },
    "percussion": {
      code: "v59",
      point: 40,
      line: 2
    },
    "soprano": {
      code: "vad",
      point: 40,
      line: 4
    },
    "mezzo-soprano": {
      code: "vad",
      point: 40,
      line: 3
    },
    "baritone-c": {
      code: "vad",
      point: 40,
      line: 0
    },
    "baritone-f": {
      code: "v79",
      point: 40,
      line: 2
    },
    "subbass": {
      code: "v79",
      point: 40,
      line: 0
    },
    "french": {
      code: "v83",
      point: 40,
      line: 4
    },
    "treble_small": {
      code: "v83",
      point: 32,
      line: 3
    },
    "bass_small": {
      code: "v79",
      point: 32,
      line: 1
    },
    "alto_small": {
      code: "vad",
      point: 32,
      line: 2
    },
    "tenor_small": {
      code: "vad",
      point: 32,
      line: 1
    },
    "soprano_small": {
      code: "vad",
      point: 32,
      line: 4
    },
    "mezzo-soprano_small": {
      code: "vad",
      point: 32,
      line: 3
    },
    "baritone-c_small": {
      code: "vad",
      point: 32,
      line: 0
    },
    "baritone-f_small": {
      code: "v79",
      point: 32,
      line: 2
    },
    "subbass_small": {
      code: "v79",
      point: 32,
      line: 0
    },
    "french_small": {
      code: "v83",
      point: 32,
      line: 4
    },
    "percussion_small": {
      code: "v59",
      point: 32,
      line: 2
    }
  };

  // ## Prototype Methods
  Vex.Inherit(Clef, Vex.Flow.StaveModifier, {
    // Create a new clef. The parameter `clef` must be a key from
    // `Clef.types`.
    init: function(clef) {
      var superclass = Vex.Flow.Clef.superclass;
      superclass.init.call(this);

      this.clef = Vex.Flow.Clef.types[clef];
      L("Creating clef:", clef);
    },

    // Add this clef to the start of the given `stave`.
    addModifier: function(stave) {
      var glyph = new Vex.Flow.Glyph(this.clef.code, this.clef.point);
      this.placeGlyphOnLine(glyph, stave, this.clef.line);
      stave.addGlyph(glyph);
    },

    // Add this clef to the end of the given `stave`.
    addEndModifier: function(stave) {
      var glyph = new Vex.Flow.Glyph(this.clef.code, this.clef.point);
      this.placeGlyphOnLine(glyph, stave, this.clef.line);
      stave.addEndGlyph(glyph);
    }
  });

  return Clef;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements some standard music theory routines.
//
// requires: vex.js   (Vex)
// requires: flow.js  (Vex.Flow)

/**
 * @constructor
 */
Vex.Flow.Music = (function() {
  function Music() {
    this.init();
  }

  Music.NUM_TONES = 12;
  Music.roots = [ "c", "d", "e", "f", "g", "a", "b" ];
  Music.root_values = [ 0, 2, 4, 5, 7, 9, 11 ];
  Music.root_indices = {
    "c": 0,
    "d": 1,
    "e": 2,
    "f": 3,
    "g": 4,
    "a": 5,
    "b": 6
  };

  Music.canonical_notes = [
    "c", "c#", "d", "d#",
    "e", "f", "f#", "g",
    "g#", "a", "a#", "b"
  ];

  Music.diatonic_intervals = [
    "unison", "m2", "M2", "m3", "M3",
    "p4", "dim5", "p5", "m6", "M6",
    "b7", "M7", "octave"
  ];

  Music.diatonic_accidentals = {
    "unison": {note: 0, accidental: 0},
    "m2":     {note: 1, accidental: -1},
    "M2":     {note: 1, accidental: 0},
    "m3":     {note: 2, accidental: -1},
    "M3":     {note: 2, accidental: 0},
    "p4":     {note: 3, accidental: 0},
    "dim5":   {note: 4, accidental: -1},
    "p5":     {note: 4, accidental: 0},
    "m6":     {note: 5, accidental: -1},
    "M6":     {note: 5, accidental: 0},
    "b7":     {note: 6, accidental: -1},
    "M7":     {note: 6, accidental: 0},
    "octave": {note: 7, accidental: 0}
  };

  Music.intervals = {
    "u":  0, "unison": 0,
    "m2": 1, "b2": 1, "min2": 1, "S": 1, "H": 1,
    "2": 2, "M2": 2, "maj2": 2, "T": 2, "W": 2,
    "m3": 3, "b3": 3, "min3": 3,
    "M3": 4, "3": 4, "maj3": 4,
    "4":  5, "p4":  5,
    "#4": 6, "b5": 6, "aug4": 6, "dim5": 6,
    "5":  7, "p5":  7,
    "#5": 8, "b6": 8, "aug5": 8,
    "6":  9, "M6":  9, "maj6": 9,
    "b7": 10, "m7": 10, "min7": 10, "dom7": 10,
    "M7": 11, "maj7": 11,
    "8": 12, "octave": 12
  };

  Music.scales = {
    major: [2, 2, 1, 2, 2, 2, 1],
    dorian: [2, 1, 2, 2, 2, 1, 2],
    mixolydian: [2, 2, 1, 2, 2, 1, 2],
    minor: [2, 1, 2, 2, 1, 2, 2]
  };

  Music.accidentals = [ "bb", "b", "n", "#", "##" ];

  Music.noteValues = {
    'c':   { root_index: 0, int_val: 0 },
    'cn':  { root_index: 0, int_val: 0 },
    'c#':  { root_index: 0, int_val: 1 },
    'c##': { root_index: 0, int_val: 2 },
    'cb':  { root_index: 0, int_val: 11 },
    'cbb': { root_index: 0, int_val: 10 },
    'd':   { root_index: 1, int_val: 2 },
    'dn':  { root_index: 1, int_val: 2 },
    'd#':  { root_index: 1, int_val: 3 },
    'd##': { root_index: 1, int_val: 4 },
    'db':  { root_index: 1, int_val: 1 },
    'dbb': { root_index: 1, int_val: 0 },
    'e':   { root_index: 2, int_val: 4 },
    'en':  { root_index: 2, int_val: 4 },
    'e#':  { root_index: 2, int_val: 5 },
    'e##': { root_index: 2, int_val: 6 },
    'eb':  { root_index: 2, int_val: 3 },
    'ebb': { root_index: 2, int_val: 2 },
    'f':   { root_index: 3, int_val: 5 },
    'fn':  { root_index: 3, int_val: 5 },
    'f#':  { root_index: 3, int_val: 6 },
    'f##': { root_index: 3, int_val: 7 },
    'fb':  { root_index: 3, int_val: 4 },
    'fbb': { root_index: 3, int_val: 3 },
    'g':   { root_index: 4, int_val: 7 },
    'gn':  { root_index: 4, int_val: 7 },
    'g#':  { root_index: 4, int_val: 8 },
    'g##': { root_index: 4, int_val: 9 },
    'gb':  { root_index: 4, int_val: 6 },
    'gbb': { root_index: 4, int_val: 5 },
    'a':   { root_index: 5, int_val: 9 },
    'an':  { root_index: 5, int_val: 9 },
    'a#':  { root_index: 5, int_val: 10 },
    'a##': { root_index: 5, int_val: 11 },
    'ab':  { root_index: 5, int_val: 8 },
    'abb': { root_index: 5, int_val: 7 },
    'b':   { root_index: 6, int_val: 11 },
    'bn':  { root_index: 6, int_val: 11 },
    'b#':  { root_index: 6, int_val: 0 },
    'b##': { root_index: 6, int_val: 1 },
    'bb':  { root_index: 6, int_val: 10 },
    'bbb': { root_index: 6, int_val: 9 }
  };

  Music.prototype = {
    init: function() {},

    isValidNoteValue: function(note) {
      if (note == null || note < 0 || note >= Vex.Flow.Music.NUM_TONES)
        return false;
      return true;
    },

    isValidIntervalValue: function(interval) {
      return this.isValidNoteValue(interval);
    },

    getNoteParts: function(noteString) {
      if (!noteString || noteString.length < 1)
        throw new Vex.RERR("BadArguments", "Invalid note name: " + noteString);

      if (noteString.length > 3)
        throw new Vex.RERR("BadArguments", "Invalid note name: " + noteString);

      var note = noteString.toLowerCase();

      var regex = /^([cdefgab])(b|bb|n|#|##)?$/;
      var match = regex.exec(note);

      if (match != null) {
        var root = match[1];
        var accidental = match[2];

        return {
          'root': root,
          'accidental': accidental
        };
      } else {
        throw new Vex.RERR("BadArguments", "Invalid note name: " + noteString);
      }
    },

    getKeyParts: function(keyString) {
      if (!keyString || keyString.length < 1)
        throw new Vex.RERR("BadArguments", "Invalid key: " + keyString);

      var key = keyString.toLowerCase();

      // Support Major, Minor, Melodic Minor, and Harmonic Minor key types.
      var regex = /^([cdefgab])(b|#)?(mel|harm|m|M)?$/;
      var match = regex.exec(key);

      if (match != null) {
        var root = match[1];
        var accidental = match[2];
        var type = match[3];

        // Unspecified type implies major
        if (!type) type = "M";

        return {
          'root': root,
          'accidental': accidental,
          'type': type
        };
      } else {
        throw new Vex.RERR("BadArguments", "Invalid key: " + keyString);
      }
    },

    getNoteValue: function(noteString) {
      var value = Music.noteValues[noteString];
      if (value == null)
        throw new Vex.RERR("BadArguments", "Invalid note name: " + noteString);

      return value.int_val;
    },

    getIntervalValue: function(intervalString) {
      var value = Music.intervals[intervalString];
      if (value == null)
        throw new Vex.RERR("BadArguments",
                           "Invalid interval name: " + intervalString);

      return value;
    },

    getCanonicalNoteName: function(noteValue) {
      if (!this.isValidNoteValue(noteValue))
        throw new Vex.RERR("BadArguments",
                           "Invalid note value: " + noteValue);

      return Music.canonical_notes[noteValue];
    },

    getCanonicalIntervalName: function(intervalValue) {
      if (!this.isValidIntervalValue(intervalValue))
        throw new Vex.RERR("BadArguments",
                           "Invalid interval value: " + intervalValue);

      return Music.diatonic_intervals[intervalValue];
    },

    /* Given a note, interval, and interval direction, product the
     * relative note.
     */
    getRelativeNoteValue: function(noteValue, intervalValue, direction) {
      if (direction == null) direction = 1;
      if (direction != 1 && direction != -1)
        throw new Vex.RERR("BadArguments", "Invalid direction: " + direction);

      var sum = (noteValue + (direction * intervalValue)) % Music.NUM_TONES;
      if (sum < 0) sum += Music.NUM_TONES;

      return sum;
    },

    getRelativeNoteName: function(root, noteValue) {
      var parts = this.getNoteParts(root);
      var rootValue = this.getNoteValue(parts.root);
      var interval = noteValue - rootValue;

      if (Math.abs(interval) > Music.NUM_TONES - 3) {
        var multiplier = 1;
        if (interval > 0 ) multiplier = -1;

        // Possibly wrap around. (Add +1 for modulo operator)
        var reverse_interval = (((noteValue + 1) + (rootValue + 1)) %
          Music.NUM_TONES) * multiplier;

        if (Math.abs(reverse_interval) > 2) {
          throw new Vex.RERR("BadArguments", "Notes not related: " + root + ", " +
                            noteValue);
        } else {
          interval = reverse_interval;
        }
      }

      if (Math.abs(interval) > 2)
          throw new Vex.RERR("BadArguments", "Notes not related: " + root + ", " +
                            noteValue);

      var relativeNoteName = parts.root;
      var i;
      if (interval > 0) {
        for (i = 1; i <= interval; ++i)
          relativeNoteName += "#";
      } else if (interval < 0) {
        for (i = -1; i >= interval; --i)
          relativeNoteName += "b";
      }

      return relativeNoteName;
    },

    /* Return scale tones, given intervals. Each successive interval is
     * relative to the previous one, e.g., Major Scale:
     *
     *   TTSTTTS = [2,2,1,2,2,2,1]
     *
     * When used with key = 0, returns C scale (which is isomorphic to
     * interval list).
     */
    getScaleTones: function(key, intervals) {
      var tones = [];
      tones.push(key);

      var nextNote = key;
      for (var i = 0; i < intervals.length; ++i) {
        nextNote = this.getRelativeNoteValue(nextNote,
                                             intervals[i]);
        if (nextNote != key) tones.push(nextNote);
      }

      return tones;
    },

    /* Returns the interval of a note, given a diatonic scale.
     *
     * E.g., Given the scale C, and the note E, returns M3
     */
    getIntervalBetween: function(note1, note2, direction) {
      if (direction == null) direction = 1;
      if (direction != 1 && direction != -1)
        throw new Vex.RERR("BadArguments", "Invalid direction: " + direction);
      if (!this.isValidNoteValue(note1) || !this.isValidNoteValue(note2))
        throw new Vex.RERR("BadArguments",
                           "Invalid notes: " + note1 + ", " + note2);

      var difference;
      if (direction == 1)
        difference = note2 - note1;
      else
        difference = note1 - note2;

      if (difference < 0) difference += Music.NUM_TONES;
      return difference;
    }
  };

  return Music;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements diatonic key management.
//
// requires: vex.js   (Vex)
// requires: flow.js  (Vex.Flow)
// requires: music.js (Vex.Flow.Music)

/**
 * @constructor
 */
Vex.Flow.KeyManager = (function() {
  function KeyManager(key) {
    this.init(key);
  }

  KeyManager.scales = {
    "M": Vex.Flow.Music.scales.major,
    "m": Vex.Flow.Music.scales.minor
  };

  KeyManager.prototype = {
    init: function(key) {
      this.music = new Vex.Flow.Music();
      this.setKey(key);
    },

    setKey: function(key) {
      this.key = key;
      this.reset();
      return this;
    },

    getKey: function() { return this.key; },

    reset: function() {
      this.keyParts = this.music.getKeyParts(this.key);

      this.keyString = this.keyParts.root;
      if (this.keyParts.accidental) this.keyString += this.keyParts.accidental;

      var is_supported_type = KeyManager.scales[this.keyParts.type];
      if (!is_supported_type)
        throw new Vex.RERR("BadArguments", "Unsupported key type: " + this.key);

      this.scale = this.music.getScaleTones(
          this.music.getNoteValue(this.keyString),
          Vex.Flow.KeyManager.scales[this.keyParts.type]);

      this.scaleMap = {};
      this.scaleMapByValue = {};
      this.originalScaleMapByValue = {};

      var noteLocation = Vex.Flow.Music.root_indices[this.keyParts.root];

      for (var i = 0; i < Vex.Flow.Music.roots.length; ++i) {
        var index = (noteLocation + i) % Vex.Flow.Music.roots.length;
        var rootName = Vex.Flow.Music.roots[index];

        var noteName = this.music.getRelativeNoteName(rootName, this.scale[i]);
        this.scaleMap[rootName] = noteName;
        this.scaleMapByValue[this.scale[i]] = noteName;
        this.originalScaleMapByValue[this.scale[i]] = noteName;
      }

      return this;
    },

    getAccidental: function(key) {
      var root = this.music.getKeyParts(key).root;
      var parts = this.music.getNoteParts(this.scaleMap[root]);

      return {
        note: this.scaleMap[root],
        accidental: parts.accidental
      };
    },

    selectNote: function(note) {
      note = note.toLowerCase();
      var parts = this.music.getNoteParts(note);

      // First look for matching note in our altered scale
      var scaleNote = this.scaleMap[parts.root];
      var modparts = this.music.getNoteParts(scaleNote);

      if (scaleNote == note) return {
        "note": scaleNote,
        "accidental": parts.accidental,
        "change": false
      };

      // Then search for a note of equivalent value in our altered scale
      var valueNote = this.scaleMapByValue[this.music.getNoteValue(note)];
      if (valueNote != null) {
        return {
          "note": valueNote,
          "accidental": this.music.getNoteParts(valueNote).accidental,
          "change": false
        };
      }

      // Then search for a note of equivalent value in the original scale
      var originalValueNote = this.originalScaleMapByValue[
        this.music.getNoteValue(note)];
      if (originalValueNote != null) {
        this.scaleMap[modparts.root] = originalValueNote;
        delete this.scaleMapByValue[this.music.getNoteValue(scaleNote)];
        this.scaleMapByValue[this.music.getNoteValue(note)] = originalValueNote;
        return {
          "note": originalValueNote,
          "accidental": this.music.getNoteParts(originalValueNote).accidental,
          "change": true
        };
      }

      // Then try to unmodify a currently modified note.
      if (modparts.root == note) {
        delete this.scaleMapByValue[
          this.music.getNoteValue(this.scaleMap[parts.root])];
        this.scaleMapByValue[this.music.getNoteValue(modparts.root)] =
          modparts.root;
        this.scaleMap[modparts.root] = modparts.root;
        return {
          "note": modparts.root,
          "accidental": null,
          "change": true
        };
      }

      // Last resort -- shitshoot
      delete this.scaleMapByValue[
        this.music.getNoteValue(this.scaleMap[parts.root])];
      this.scaleMapByValue[this.music.getNoteValue(note)] = note;

      delete this.scaleMap[modparts.root];
      this.scaleMap[modparts.root] = note;

      return {
        "note": note,
        "accidental": parts.accidental,
        "change": true
      };
    }
  };

  return KeyManager;
}());
// Vex Flow
// Mohit Muthanna <mohit@muthanna.com>
//
// Support for different rendering contexts: Canvas, Raphael
//
// Copyright Mohit Cheppudira 2010

/* global document: false */

Vex.Flow.Renderer = (function() {
  function Renderer(sel, backend) {
    if (arguments.length > 0) this.init(sel, backend);
  }

  Renderer.Backends = {
    CANVAS: 1,
    RAPHAEL: 2,
    SVG: 3,
    VML: 4
  };

  //End of line types
  Renderer.LineEndType = {
      NONE: 1,        // No leg
      UP: 2,          // Upward leg
      DOWN: 3         // Downward leg
  };

  // Set this to true if you're using VexFlow inside a runtime
  // that does not allow modifiying canvas objects. There is a small
  // performance degradation due to the extra indirection.
  Renderer.USE_CANVAS_PROXY = false;

  Renderer.buildContext = function(sel,
      backend, width, height, background) {
    var renderer = new Renderer(sel, backend);
    if (width && height) { renderer.resize(width, height); }

    if (!background) background = "#eed";
    var ctx = renderer.getContext();
    ctx.setBackgroundFillStyle(background);
    return ctx;
  };

  Renderer.getCanvasContext = function(sel, width, height, background) {
    return Renderer.buildContext(sel, Renderer.Backends.CANVAS,
        width, height, background);
  };

  Renderer.getRaphaelContext = function(sel, width, height, background) {
    return Renderer.buildContext(sel, Renderer.Backends.RAPHAEL,
        width, height, background);
  };

  Renderer.bolsterCanvasContext = function(ctx) {
    if (Renderer.USE_CANVAS_PROXY) {
      return new Vex.Flow.CanvasContext(ctx);
    }

    var methods = ["clear", "setFont", "setRawFont", "setFillStyle", "setBackgroundFillStyle",
                   "setStrokeStyle", "setShadowColor", "setShadowBlur", "setLineWidth"];
    ctx.vexFlowCanvasContext = ctx;

    for (var i in methods) {
      var method = methods[i];
      ctx[method] = Vex.Flow.CanvasContext.prototype[method];
    }

    return ctx;
  };

  //Draw a dashed line (horizontal, vertical or diagonal
  //dashPattern = [3,3] draws a 3 pixel dash followed by a three pixel space.
  //setting the second number to 0 draws a solid line.
  Renderer.drawDashedLine = function(context, fromX, fromY, toX, toY, dashPattern) {
    context.beginPath();

    var dx = toX - fromX;
    var dy = toY - fromY;
    var angle = Math.atan2(dy, dx);
    var x = fromX;
    var y = fromY;
    context.moveTo(fromX, fromY);
    var idx = 0;
    var draw = true;
    while (!((dx < 0 ? x <= toX : x >= toX) && (dy < 0 ? y <= toY : y >= toY))) {
      var dashLength = dashPattern[idx++ % dashPattern.length];
      var nx = x + (Math.cos(angle) * dashLength);
      x = dx < 0 ? Math.max(toX, nx) : Math.min(toX, nx);
      var ny = y + (Math.sin(angle) * dashLength);
      y = dy < 0 ? Math.max(toY, ny) : Math.min(toY, ny);
      if (draw) {
        context.lineTo(x, y);
      } else {
        context.moveTo(x, y);
      }
        draw = !draw;
    }

    context.closePath();
    context.stroke();
  };

  Renderer.prototype = {
    init: function(sel, backend) {
      // Verify selector
      this.sel = sel;
      if (!this.sel) throw new Vex.RERR("BadArgument",
          "Invalid selector for renderer.");

      // Get element from selector
      this.element = document.getElementById(sel);
      if (!this.element) this.element = sel;

      // Verify backend and create context
      this.ctx = null;
      this.paper = null;
      this.backend = backend;
      if (this.backend == Renderer.Backends.CANVAS) {
        // Create context.
        if (!this.element.getContext) throw new Vex.RERR("BadElement",
          "Can't get canvas context from element: " + sel);
        this.ctx = Renderer.bolsterCanvasContext(
            this.element.getContext('2d'));
      } else if (this.backend == Renderer.Backends.RAPHAEL) {
        this.ctx = new Vex.Flow.RaphaelContext(this.element);
      } else {
        throw new Vex.RERR("InvalidBackend",
          "No support for backend: " + this.backend);
      }
    },

    resize: function(width, height) {
      if (this.backend == Renderer.Backends.CANVAS) {
        if (!this.element.getContext) throw new Vex.RERR("BadElement",
          "Can't get canvas context from element: " + this.sel);
        this.element.width = width;
        this.element.height = height;
        this.ctx = Renderer.bolsterCanvasContext(
            this.element.getContext('2d'));
      } else {
        this.ctx.resize(width, height);
      }

      return this;
    },

    getContext: function() { return this.ctx; }
  };

  return Renderer;
}());


// Vex Flow
// Mohit Muthanna <mohit@muthanna.com>
//
// A rendering context for the Raphael backend.
//
// Copyright Mohit Cheppudira 2010

/** @constructor */
Vex.Flow.RaphaelContext = (function() {
  function RaphaelContext(element) {
    if (arguments.length > 0) this.init(element);
  }

  RaphaelContext.prototype = {
    init: function(element) {
      this.element = element;
      this.paper = Raphael(element);
      this.path = "";
      this.pen = {x: 0, y: 0};
      this.lineWidth = 1.0;
      this.state = {
        scale: { x: 1, y: 1 },
        font_family: "Arial",
        font_size: 8,
        font_weight: 800
      };

      this.attributes = {
        "stroke-width": 0.3,
        "fill": "black",
        "stroke": "black",
        "font": "10pt Arial"
      };

      this.background_attributes = {
        "stroke-width": 0,
        "fill": "white",
        "stroke": "white",
        "font": "10pt Arial"
      };

      this.shadow_attributes = {
        width: 0,
        color: "black"
      };

      this.state_stack= [];
    },

    setFont: function(family, size, weight) {
      this.state.font_family = family;
      this.state.font_size = size;
      this.state.font_weight = weight;
      this.attributes.font = (this.state.font_weight || "") + " " +
        (this.state.font_size * this.state.scale.x) + "pt " +
        this.state.font_family;
      return this;
    },

    setRawFont: function(font) {
      this.attributes.font = font;
      return this;
    },

    setFillStyle: function(style) {
      this.attributes.fill = style;
      return this;
    },

    setBackgroundFillStyle: function(style) {
      this.background_attributes.fill = style;
      this.background_attributes.stroke = style;
      return this;
    },

    setStrokeStyle: function(style) {
      this.attributes.stroke = style;
      return this;
    },

    setShadowColor: function(style) {
      this.shadow_attributes.color = style;
      return this;
    },

    setShadowBlur: function(blur) {
      this.shadow_attributes.width = blur;
      return this;
    },

    setLineWidth: function(width) {
      this.attributes["stroke-width"] = width;
      this.lineWidth = width;
    },

    scale: function(x, y) {
      this.state.scale = { x: x, y: y };
      this.attributes.scale = x + "," + y + ",0,0";
      this.attributes.font = this.state.font_size * this.state.scale.x + "pt " +
        this.state.font_family;
      this.background_attributes.scale = x + "," + y + ",0,0";
      this.background_attributes.font = this.state.font_size *
        this.state.scale.x + "pt " +
        this.state.font_family;
      return this;
    },

    clear: function() { this.paper.clear(); },

    resize: function(width, height) {
      this.element.style.width = width;
      this.paper.setSize(width, height);
      return this;
    },

    rect: function(x, y, width, height) {
      if (height < 0) {
        y += height;
        height = -height;
      }

      this.paper.rect(x, y, width - 0.5, height - 0.5).
        attr(this.attributes).
        attr("fill", "none").
        attr("stroke-width", this.lineWidth); return this;
    },

    fillRect: function(x, y, width, height) {
      if (height < 0) {
        y += height;
        height = -height;
      }

      this.paper.rect(x, y, width - 0.5, height - 0.5).
        attr(this.attributes);
      return this;
    },

    clearRect: function(x, y, width, height) {
      if (height < 0) {
        y += height;
        height = -height;
      }

      this.paper.rect(x, y, width - 0.5, height - 0.5).
        attr(this.background_attributes);
      return this;
    },

    beginPath: function() {
      this.path = "";
      this.pen.x = 0;
      this.pen.y = 0;
      return this;
    },

    moveTo: function(x, y) {
      this.path += "M" + x + "," + y;
      this.pen.x = x;
      this.pen.y = y;
      return this;
    },

    lineTo: function(x, y) {
      this.path += "L" + x + "," + y;
      this.pen.x = x;
      this.pen.y = y;
      return this;
    },

    bezierCurveTo: function(x1, y1, x2, y2, x, y) {
      this.path += "C" +
        x1 + "," +
        y1 + "," +
        x2 + "," +
        y2 + "," +
        x + "," +
        y;
      this.pen.x = x;
      this.pen.y = y;
      return this;
    },

    quadraticCurveTo: function(x1, y1, x, y) {
      this.path += "Q" +
        x1 + "," +
        y1 + "," +
        x + "," +
        y;
      this.pen.x = x;
      this.pen.y = y;
      return this;
    },

    // This is an attempt (hack) to simulate the HTML5 canvas
    // arc method.
    arc: function(x, y, radius, startAngle, endAngle, antiClockwise) {
      function normalizeAngle(angle) {
        while (angle < 0) {
          angle += Math.PI * 2;
        }

        while (angle > Math.PI * 2) {
          angle -= Math.PI * 2;
        }
        return angle;
      }

      startAngle = normalizeAngle(startAngle);
      endAngle = normalizeAngle(endAngle);

      if (startAngle > endAngle) {
          var tmp = startAngle;
          startAngle = endAngle;
          endAngle = tmp;
          antiClockwise = !antiClockwise;
      }

      var delta = endAngle - startAngle;

      if (delta > Math.PI) {
          this.arcHelper(x, y, radius, startAngle, startAngle + delta / 2,
                         antiClockwise);
          this.arcHelper(x, y, radius, startAngle + delta / 2, endAngle,
                         antiClockwise);
      }
      else {
          this.arcHelper(x, y, radius, startAngle, endAngle, antiClockwise);
      }
      return this;
    },

    arcHelper: function(x, y, radius, startAngle, endAngle, antiClockwise) {
      var x1 = x + radius * Math.cos(startAngle);
      var y1 = y + radius * Math.sin(startAngle);

      var x2 = x + radius * Math.cos(endAngle);
      var y2 = y + radius * Math.sin(endAngle);

      var largeArcFlag = 0;
      var sweepFlag = 0;
      if (antiClockwise) {
        sweepFlag = 1;
        if (endAngle - startAngle < Math.PI)
          largeArcFlag = 1;
      }
      else if (endAngle - startAngle > Math.PI) {
          largeArcFlag = 1;
      }

      this.path += "M" + x1 + "," + y1 + "," + "A" +
        radius + "," + radius + "," + "0," + largeArcFlag + "," + sweepFlag + "," +
        x2 + "," + y2 + "M" + this.pen.x + "," + this.pen.y;
    },

    // Adapted from the source for Raphael's Element.glow
    glow: function() {
      var out = this.paper.set();
      if (this.shadow_attributes.width > 0) {
        var sa = this.shadow_attributes;
        var num_paths = sa.width / 2;
        for (var i = 1; i <= num_paths; i++) {
          out.push(this.paper.path(this.path).attr({
            stroke: sa.color,
            "stroke-linejoin": "round",
            "stroke-linecap": "round",
            "stroke-width": +(sa.width / num_paths * i).toFixed(3),
            opacity: +((sa.opacity || 0.3) / num_paths).toFixed(3)
          }));
        }
      }
      return out;
    },

    fill: function() {
      var elem = this.paper.path(this.path).
        attr(this.attributes).
        attr("stroke-width", 0);
      this.glow(elem);
      return this;
    },

    stroke: function() {
      var elem = this.paper.path(this.path).
        attr(this.attributes).
        attr("fill", "none").
        attr("stroke-width", this.lineWidth);
      this.glow(elem);
      return this;
    },

    closePath: function() {
      this.path += "Z";
      return this;
    },

    measureText: function(text) {
      var txt = this.paper.text(0, 0, text).
        attr(this.attributes).
        attr("fill", "none").
        attr("stroke", "none");

      return {
        width: txt.getBBox().width,
        height: txt.getBBox().height
      };
    },

    fillText: function(text, x, y) {
      this.paper.text(x + (this.measureText(text).width / 2),
          (y - (this.state.font_size / (2.25 * this.state.scale.y))), text).
        attr(this.attributes);
      return this;
    },

    save: function() {
      // TODO(mmuthanna): State needs to be deep-copied.
      this.state_stack.push({
        state: {
          font_family: this.state.font_family
        },
        attributes: {
          font: this.attributes.font,
          fill: this.attributes.fill,
          stroke: this.attributes.stroke,
          "stroke-width": this.attributes["stroke-width"]
        },
        shadow_attributes: {
          width: this.shadow_attributes.width,
          color: this.shadow_attributes.color
        }
      });
      return this;
    },

    restore: function() {
      // TODO(0xfe): State needs to be deep-restored.
      var state = this.state_stack.pop();
      this.state.font_family = state.state.font_family;
      this.attributes.font = state.attributes.font;
      this.attributes.fill = state.attributes.fill;
      this.attributes.stroke = state.attributes.stroke;
      this.attributes["stroke-width"] = state.attributes["stroke-width"];
      this.shadow_attributes.width = state.shadow_attributes.width;
      this.shadow_attributes.color = state.shadow_attributes.color;
      return this;
    }
  };

  return RaphaelContext;
}());
// Vex Flow
// Mohit Muthanna <mohit@muthanna.com>
//
// A rendering context for the Raphael backend.
//
// Copyright Mohit Cheppudira 2010

/** @constructor */
Vex.Flow.CanvasContext = (function() {
  function CanvasContext(context) {
    if (arguments.length > 0) this.init(context);
  }

  CanvasContext.WIDTH = 600;
  CanvasContext.HEIGHT = 400;

  CanvasContext.prototype = {
    init: function(context) {
      // Use a name that is unlikely to clash with a canvas context
      // property
      this.vexFlowCanvasContext = context;
      if (!context.canvas) {
        this.canvas = {
          width: CanvasContext.WIDTH,
          height: CanvasContext.HEIGHT
        };
      } else {
        this.canvas = this.context.canvas;
      }
    },

    clear: function() {
      this.vexFlowCanvasContext.clearRect(0, 0, this.canvas.width, this.canvas.height);
    },

    setFont: function(family, size, weight) {
      this.vexFlowCanvasContext.font = (weight || "") + " " + size + "pt " + family;
      return this;
    },

    setRawFont: function(font) {
      this.vexFlowCanvasContext.font = font;
      return this;
    },

    setFillStyle: function(style) {
      this.vexFlowCanvasContext.fillStyle = style;
      return this;
    },

    setBackgroundFillStyle: function(style) {
      this.background_fillStyle = style;
      return this;
    },

    setStrokeStyle: function(style) {
      this.vexFlowCanvasContext.strokeStyle = style;
      return this;
    },

    setShadowColor: function(style) {
      this.vexFlowCanvasContext.shadowColor = style;
      return this;
    },

    setShadowBlur: function(blur) {
      this.vexFlowCanvasContext.shadowBlur = blur;
      return this;
    },

    setLineWidth: function(width) {
      this.vexFlowCanvasContext.lineWidth = width;
      return this;
    },

    scale: function(x, y) {
      return this.vexFlowCanvasContext.scale(parseFloat(x), parseFloat(y));
    },

    resize: function(width, height) {
      return this.vexFlowCanvasContext.resize(
          parseInt(width, 10), parseInt(height, 10));
    },

    rect: function(x, y, width, height) {
      return this.vexFlowCanvasContext.rect(x, y, width, height);
    },

    fillRect: function(x, y, width, height) {
      return this.vexFlowCanvasContext.fillRect(x, y, width, height);
    },

    clearRect: function(x, y, width, height) {
      return this.vexFlowCanvasContext.clearRect(x, y, width, height);
    },

    beginPath: function() {
      return this.vexFlowCanvasContext.beginPath();
    },

    moveTo: function(x, y) {
      return this.vexFlowCanvasContext.moveTo(x, y);
    },

    lineTo: function(x, y) {
      return this.vexFlowCanvasContext.lineTo(x, y);
    },

    bezierCurveTo: function(x1, y1, x2, y2, x, y) {
      return this.vexFlowCanvasContext.bezierCurveTo(x1, y1, x2, y2, x, y);
    },

    quadraticCurveTo: function(x1, y1, x, y) {
      return this.vexFlowCanvasContext.quadraticCurveTo(x1, y1, x, y);
    },

    // This is an attempt (hack) to simulate the HTML5 canvas
    // arc method.
    arc: function(x, y, radius, startAngle, endAngle, antiClockwise) {
      return this.vexFlowCanvasContext.arc(x, y, radius, startAngle, endAngle, antiClockwise);
    },

    // Adapted from the source for Raphael's Element.glow
    glow: function() {
      return this.vexFlowCanvasContext.glow();
    },

    fill: function() {
      return this.vexFlowCanvasContext.fill();
    },

    stroke: function() {
      return this.vexFlowCanvasContext.stroke();
    },

    closePath: function() {
      return this.vexFlowCanvasContext.closePath();
    },

    measureText: function(text) {
      return this.vexFlowCanvasContext.measureText(text);
    },

    fillText: function(text, x, y) {
      return this.vexFlowCanvasContext.fillText(text, x, y);
    },

    save: function() {
      return this.vexFlowCanvasContext.save();
    },

    restore: function() {
      return this.vexFlowCanvasContext.restore();
    }
  };

  return CanvasContext;
}());
// Vex Flow Notation
// Author Larry Kuhns 2011
// Implements barlines (single, double, repeat, end)
//
// Requires vex.js.

/**
 * @constructor
 */
Vex.Flow.Barline = (function() {
  function Barline(type, x) {
    if (arguments.length > 0) this.init(type, x);
  }

  Barline.type = {
    SINGLE: 1,
    DOUBLE: 2,
    END: 3,
    REPEAT_BEGIN: 4,
    REPEAT_END: 5,
    REPEAT_BOTH: 6,
    NONE: 7
  };

  var THICKNESS = Vex.Flow.STAVE_LINE_THICKNESS;

  Vex.Inherit(Barline, Vex.Flow.StaveModifier, {
    init: function(type, x) {
      Barline.superclass.init.call(this);
      this.barline = type;
      this.x = x;    // Left most x for the stave
    },

    getCategory: function() { return "barlines"; },
    setX: function(x) { this.x = x; return this; },

    // Draw barlines
    draw: function(stave, x_shift) {
      x_shift = typeof x_shift !== 'number' ? 0 : x_shift;

      switch (this.barline) {
        case Barline.type.SINGLE:
          this.drawVerticalBar(stave, this.x, false);
          break;
        case Barline.type.DOUBLE:
          this.drawVerticalBar(stave, this.x, true);
          break;
        case Barline.type.END:
          this.drawVerticalEndBar(stave, this.x);
          break;
        case Barline.type.REPEAT_BEGIN:
          // If the barline is shifted over (in front of clef/time/key)
          // Draw vertical bar at the beginning.
          if (x_shift > 0) {
            this.drawVerticalBar(stave, this.x);
          }
          this.drawRepeatBar(stave, this.x + x_shift, true);
          break;
        case Barline.type.REPEAT_END:
          this.drawRepeatBar(stave, this.x, false);
          break;
        case Barline.type.REPEAT_BOTH:
          this.drawRepeatBar(stave, this.x, false);
          this.drawRepeatBar(stave, this.x, true);
          break;
        default:
          // Default is NONE, so nothing to draw
          break;
      }
    },

    drawVerticalBar: function(stave, x, double_bar) {
      if (!stave.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw stave without canvas context.");
      var top_line = stave.getYForLine(0);
      var bottom_line = stave.getYForLine(stave.options.num_lines - 1) + (THICKNESS / 2);
      if (double_bar)
        stave.context.fillRect(x - 3, top_line, 1, bottom_line - top_line + 1);
      stave.context.fillRect(x, top_line, 1, bottom_line - top_line + 1);
    },

    drawVerticalEndBar: function(stave, x) {
      if (!stave.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw stave without canvas context.");

      var top_line = stave.getYForLine(0);
      var bottom_line = stave.getYForLine(stave.options.num_lines - 1) + (THICKNESS / 2);
      stave.context.fillRect(x - 5, top_line, 1, bottom_line - top_line + 1);
      stave.context.fillRect(x - 2, top_line, 3, bottom_line - top_line + 1);
    },

    drawRepeatBar: function(stave, x, begin) {
      if (!stave.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw stave without canvas context.");

      var top_line = stave.getYForLine(0);
      var bottom_line = stave.getYForLine(stave.options.num_lines - 1) + (THICKNESS / 2);
      var x_shift = 3;

      if (!begin) {
        x_shift = -5;
      }

      stave.context.fillRect(x + x_shift, top_line, 1, bottom_line - top_line + 1);
      stave.context.fillRect(x - 2, top_line, 3, bottom_line - top_line + 1);

      var dot_radius = 2;

      // Shift dots left or right
      if (begin) {
        x_shift += 4;
      } else {
        x_shift -= 4;
      }

      var dot_x = (x + x_shift) + (dot_radius / 2);

      // calculate the y offset based on number of stave lines
      var y_offset = (stave.options.num_lines -1) *
        stave.options.spacing_between_lines_px;
      y_offset = (y_offset / 2) -
                 (stave.options.spacing_between_lines_px / 2);
      var dot_y = top_line + y_offset + (dot_radius / 2);

      // draw the top repeat dot
      stave.context.beginPath();
      stave.context.arc(dot_x, dot_y, dot_radius, 0, Math.PI * 2, false);
      stave.context.fill();

      //draw the bottom repeat dot
      dot_y += stave.options.spacing_between_lines_px;
      stave.context.beginPath();
      stave.context.arc(dot_x, dot_y, dot_radius, 0, Math.PI * 2, false);
      stave.context.fill();
    }
  });

  return Barline;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
// This class by Raffaele Viglianti, 2012 http://itisnotsound.wordpress.com/
//
// This class implements hairpins between notes.
// Hairpins can be either Crescendo or Descrescendo.

/**
 * Create a new hairpin from the specified notes.
 *
 * @constructor
 * @param {!Object} notes The notes to tie up.
 * @param {!Object} type The type of hairpin
 */
Vex.Flow.StaveHairpin = (function() {
  function StaveHairpin(notes, type) {
    if (arguments.length > 0) this.init(notes, type);
  }

  StaveHairpin.type = {
    CRESC: 1,
    DECRESC: 2
  };

  /* Helper function to convert ticks into pixels.
   * Requires a Formatter with voices joined and formatted (to
   * get pixels per tick)
   *
   * options is struct that has:
   *
   *  {
   *   height: px,
   *   y_shift: px, //vertical offset
   *   left_shift_ticks: 0, //left horizontal offset expressed in ticks
   *   right_shift_ticks: 0 // right horizontal offset expressed in ticks
   *  }
   *
   **/
  StaveHairpin.FormatByTicksAndDraw = function(ctx, formatter, notes, type, position, options) {
    var ppt = formatter.pixelsPerTick;

    if (ppt == null){
      throw new Vex.RuntimeError("BadArguments",
          "A valid Formatter must be provide to draw offsets by ticks.");}

    var l_shift_px = ppt * options.left_shift_ticks;
    var r_shift_px = ppt * options.right_shift_ticks;

    var hairpin_options = {
      height: options.height,
      y_shift:options.y_shift,
      left_shift_px:l_shift_px,
      right_shift_px:r_shift_px};

    new StaveHairpin({
      first_note: notes.first_note,
      last_note: notes.last_note
    }, type)
      .setContext(ctx)
      .setRenderOptions(hairpin_options)
      .setPosition(position)
      .draw();
  };

  StaveHairpin.prototype = {
    init: function(notes, type) {
      /**
       * Notes is a struct that has:
       *
       *  {
       *    first_note: Note,
       *    last_note: Note,
       *  }
       *
       **/

      this.notes = notes;
      this.hairpin = type;
      this.position = Vex.Flow.Modifier.Position.BELOW;

      this.context = null;

      this.render_options = {
          height: 10,
          y_shift: 0, //vertical offset
          left_shift_px: 0, //left horizontal offset
          right_shift_px: 0 // right horizontal offset
        };

      this.setNotes(notes);
    },

    setContext: function(context) { this.context = context; return this; },

    setPosition: function(position) {
      if (position == Vex.Flow.Modifier.Position.ABOVE ||
          position == Vex.Flow.Modifier.Position.BELOW)
        this.position = position;
      return this;
    },

    setRenderOptions: function(options) {
      if (options.height != null &&
          options.y_shift != null &&
          options.left_shift_px != null &&
          options.right_shift_px != null){
        this.render_options = options;
      }
      return this;
    },

    /**
     * Set the notes to attach this hairpin to.
     *
     * @param {!Object} notes The start and end notes.
     */
    setNotes: function(notes) {
      if (!notes.first_note && !notes.last_note)
        throw new Vex.RuntimeError("BadArguments",
            "Hairpin needs to have either first_note or last_note set.");

      // Success. Lets grab 'em notes.
      this.first_note = notes.first_note;
      this.last_note = notes.last_note;
      return this;
    },

    renderHairpin: function(params) {
      var ctx = this.context;
      var dis = this.render_options.y_shift + 20;
      var y_shift = params.first_y;

      if (this.position == Vex.Flow.Modifier.Position.ABOVE) {
        dis = -dis +30;
        y_shift = params.first_y - params.staff_height;
      }

      var l_shift = this.render_options.left_shift_px;
      var r_shift = this.render_options.right_shift_px;

      switch (this.hairpin) {
        case StaveHairpin.type.CRESC:
          ctx.moveTo(params.last_x + r_shift, y_shift + dis);
          ctx.lineTo(params.first_x + l_shift, y_shift +(this.render_options.height/2) + dis);
          ctx.lineTo(params.last_x + r_shift, y_shift + this.render_options.height + dis);
          break;
        case StaveHairpin.type.DECRESC:
          ctx.moveTo(params.first_x + l_shift, y_shift + dis);
          ctx.lineTo(params.last_x + r_shift, y_shift +(this.render_options.height/2) + dis);
          ctx.lineTo(params.first_x + l_shift, y_shift + this.render_options.height + dis);
          break;
        default:
          // Default is NONE, so nothing to draw
          break;
      }

      ctx.stroke();
    },

    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw Hairpin without a context.");

      var first_note = this.first_note;
      var last_note = this.last_note;

      var start = first_note.getModifierStartXY(this.position, 0);
      var end = last_note.getModifierStartXY(this.position, 0);

      this.renderHairpin({
        first_x: start.x,
        last_x: end.x,
        first_y: first_note.getStave().y + first_note.getStave().height,
        last_y: last_note.getStave().y + last_note.getStave().height,
        staff_height: first_note.getStave().height
      });
     return true;
    }
  };
  return StaveHairpin;
}());

// Vex Flow Notation
// Author Larry Kuhns 2011
// Implements voltas (repeat brackets)
//
// Requires vex.js.

Vex.Flow.Volta = (function() {
  function Volta(type, number, x, y_shift) {
    if (arguments.length > 0) this.init(type, number, x, y_shift);
  }

  Volta.type = {
    NONE: 1,
    BEGIN: 2,
    MID: 3,
    END: 4,
    BEGIN_END: 5
  };

  Vex.Inherit(Volta, Vex.Flow.StaveModifier, {
    init: function(type, number, x, y_shift) {
      Volta.superclass.init.call(this);

      this.volta = type;
      this.x = x;
      this.y_shift = y_shift;
      this.number = number;
      this.font = {
        family: "sans-serif",
        size: 9,
        weight: "bold"
      };
    },

    getCategory: function() { return "voltas"; },
    setShiftY: function(y) { this.y_shift = y; return this; },

    draw: function(stave, x) {
      if (!stave.context) throw new Vex.RERR("NoCanvasContext",
        "Can't draw stave without canvas context.");
      var ctx = stave.context;
      var width = stave.width;
      var top_y = stave.getYForTopText(stave.options.num_lines) + this.y_shift;
      var vert_height = 1.5 * stave.options.spacing_between_lines_px;
      switch(this.volta) {
        case Vex.Flow.Volta.type.BEGIN:
          ctx.fillRect(this.x + x, top_y, 1, vert_height);
          break;
        case Vex.Flow.Volta.type.END:
          width -= 5;
          ctx.fillRect(this.x + x + width, top_y, 1, vert_height);
          break;
        case Vex.Flow.Volta.type.BEGIN_END:
          width -= 3;
          ctx.fillRect(this.x + x, top_y, 1, vert_height);
          ctx.fillRect(this.x + x + width, top_y, 1, vert_height);
          break;
      }
        // If the beginning of a volta, draw measure number
      if (this.volta == Volta.type.BEGIN ||
          this.volta == Volta.type.BEGIN_END) {
        ctx.save();
        ctx.setFont(this.font.family, this.font.size, this.font.weight);
        ctx.fillText(this.number, this.x + x + 5, top_y + 15);
        ctx.restore();
      }
      ctx.fillRect(this.x + x, top_y, width, 1);
      return this;
    }
  });

  return Volta;
}());// Vex Flow Notation
// Author Larry Kuhns 2011
// Implements Repetitions (Coda, signo, D.C., etc.)
//
// Requires vex.js.

Vex.Flow.Repetition = (function() {
  function Repetition(type, x, y_shift) {
    if (arguments.length > 0) this.init(type, x, y_shift);
  }

  Repetition.type = {
    NONE: 1,         // no coda or segno
    CODA_LEFT: 2,    // coda at beginning of stave
    CODA_RIGHT: 3,   // coda at end of stave
    SEGNO_LEFT: 4,   // segno at beginning of stave
    SEGNO_RIGHT: 5,  // segno at end of stave
    DC: 6,           // D.C. at end of stave
    DC_AL_CODA: 7,   // D.C. al coda at end of stave
    DC_AL_FINE: 8,   // D.C. al Fine end of stave
    DS: 9,           // D.S. at end of stave
    DS_AL_CODA: 10,  // D.S. al coda at end of stave
    DS_AL_FINE: 11,  // D.S. al Fine at end of stave
    FINE: 12         // Fine at end of stave
  };

  Vex.Inherit(Repetition, Vex.Flow.StaveModifier, {
    init: function(type, x, y_shift) {
      Repetition.superclass.init.call(this);

      this.symbol_type = type;
      this.x = x;
      this.x_shift = 0;
      this.y_shift = y_shift;
      this.font = {
        family: "times",
        size: 12,
        weight: "bold italic"
      };
    },

    getCategory: function() { return "repetitions"; },
    setShiftX: function(x) { this.x_shift = x; return this; },
    setShiftY: function(y) { this.y_shift = y; return this; },

    draw: function(stave, x) {
      switch (this.symbol_type) {
        case Repetition.type.CODA_RIGHT:
          this.drawCodaFixed(stave, x + stave.width);
          break;
        case Repetition.type.CODA_LEFT:
          this.drawSymbolText(stave, x, "Coda", true);
          break;
        case Repetition.type.SEGNO_LEFT:
          this.drawSignoFixed(stave, x);
          break;
        case Repetition.type.SEGNO_RIGHT:
          this.drawSignoFixed(stave, x + stave.width);
          break;
        case Repetition.type.DC:
          this.drawSymbolText(stave, x, "D.C.", false);
          break;
        case Repetition.type.DC_AL_CODA:
          this.drawSymbolText(stave, x, "D.C. al", true);
          break;
        case Repetition.type.DC_AL_FINE:
          this.drawSymbolText(stave, x, "D.C. al Fine", false);
          break;
        case Repetition.type.DS:
          this.drawSymbolText(stave, x, "D.S.", false);
          break;
        case Repetition.type.DS_AL_CODA:
          this.drawSymbolText(stave, x, "D.S. al", true);
          break;
        case Repetition.type.DS_AL_FINE:
          this.drawSymbolText(stave, x, "D.S. al Fine", false);
          break;
        case Repetition.type.FINE:
          this.drawSymbolText(stave, x, "Fine", false);
          break;
        default:
          break;
      }

      return this;
    },

    drawCodaFixed: function(stave, x) {
      if (!stave.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw stave without canvas context.");

      var y = stave.getYForTopText(stave.options.num_lines) + this.y_shift;
      Vex.Flow.renderGlyph(stave.context, this.x + x + this.x_shift,
                           y + 25, 40, "v4d", true);
      return this;
    },

    drawSignoFixed: function(stave, x) {
      if (!stave.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw stave without canvas context.");
      var y = stave.getYForTopText(stave.options.num_lines) + this.y_shift;
      Vex.Flow.renderGlyph(stave.context, this.x + x + this.x_shift,
                           y + 25, 30, "v8c", true);
      return this;
    },

    drawSymbolText: function(stave, x, text, draw_coda) {
      if (!stave.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw stave without canvas context.");

      var ctx = stave.context;
      ctx.save();
      ctx.setFont(this.font.family, this.font.size, this.font.weight);
        // Default to right symbol
      var text_x = 0 + this.x_shift;
      var symbol_x = x + this.x_shift;
      if (this.symbol_type == Vex.Flow.Repetition.type.CODA_LEFT) {
          // Offset Coda text to right of stave beginning
        text_x = this.x + stave.options.vertical_bar_width;
        symbol_x = text_x + ctx.measureText(text).width + 12;
      } else {
          // Offset Signo text to left stave end
        symbol_x = this.x + x + stave.width - 5 + this.x_shift;
        text_x = symbol_x - + ctx.measureText(text).width - 12;
      }
      var y = stave.getYForTopText(stave.options.num_lines) + this.y_shift;
      if (draw_coda) {
        Vex.Flow.renderGlyph(ctx, symbol_x, y, 40, "v4d", true);
      }

      ctx.fillText(text, text_x, y + 5);
      ctx.restore();

      return this;
    }
  });

  return Repetition;
}());// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
// Author Larry Kuhns 2011
// Implements stave section names.

/**
 * @constructor
 */
Vex.Flow.StaveSection = (function() {
  function StaveSection(section, x, shift_y) {
    if (arguments.length > 0) this.init(section, x, shift_y);
  }

  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(StaveSection, Modifier, {
    init: function(section, x, shift_y) {
      StaveSection.superclass.init.call(this);

      this.setWidth(16);
      this.section = section;
      this.position = Modifier.Position.ABOVE;
      this.x = x;
      this.shift_x = 0;
      this.shift_y = shift_y;
      this.font = {
        family: "sans-serif",
        size: 12,
        weight: "bold"
      };
    },

    getCategory: function() { return "stavesection"; },
    setStaveSection: function(section) { this.section = section; return this; },
    setShiftX: function(x) { this.shift_x = x; return this; },
    setShiftY: function(y) { this.shift_y = y; return this; },

    draw: function(stave, shift_x) {
      if (!stave.context) throw new Vex.RERR("NoContext",
        "Can't draw stave section without a context.");

      var ctx = stave.context;

      ctx.save();
      ctx.lineWidth = 2;
      ctx.setFont(this.font.family, this.font.size, this.font.weight);
      var text_width = ctx.measureText("" + this.section).width;
      var width = text_width + 6;  // add left & right padding
      if (width < 18) width = 18;
      var height = 20;
        //  Seems to be a good default y
      var y = stave.getYForTopText(3) + this.shift_y;
      var x = this.x + shift_x;
      ctx.beginPath();
      ctx.lineWidth = 2;
      ctx.rect(x, y, width, height);
      ctx.stroke();
      x += (width - text_width) / 2;
      ctx.fillText("" + this.section, x, y + 16);
      ctx.restore();
      return this;
    }
  });

  return StaveSection;
}());// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
// Author Radosaw Eichler 2012
// Implements tempo marker.

/**
 * @constructor
 * @param {Object} tempo Tempo parameters: { name, duration, dots, bpm }
 */
Vex.Flow.StaveTempo = (function() {
  function StaveTempo(tempo, x, shift_y) {
    if (arguments.length > 0) this.init(tempo, x, shift_y);
  }

  Vex.Inherit(StaveTempo, Vex.Flow.StaveModifier, {
    init: function(tempo, x, shift_y) {
      StaveTempo.superclass.init.call(this);

      this.tempo = tempo;
      this.position = Vex.Flow.Modifier.Position.ABOVE;
      this.x = x;
      this.shift_x = 10;
      this.shift_y = shift_y;
      this.font = {
        family: "times",
        size: 14,
        weight: "bold"
      };
      this.render_options = {
        glyph_font_scale: 30  // font size for note
      };
    },

    getCategory: function() { return "stavetempo"; },
    setTempo: function(tempo) { this.tempo = tempo; return this; },
    setShiftX: function(x) { this.shift_x = x; return this; },
    setShiftY: function(y) { this.shift_y = y; return this; },

    draw: function(stave, shift_x) {
      if (!stave.context) throw new Vex.RERR("NoContext",
        "Can't draw stave tempo without a context.");

      var options = this.render_options;
      var scale = options.glyph_font_scale / 38;
      var name = this.tempo.name;
      var duration = this.tempo.duration;
      var dots = this.tempo.dots;
      var bpm = this.tempo.bpm;
      var font = this.font;
      var ctx = stave.context;
      var x = this.x + this.shift_x + shift_x;
      var y = stave.getYForTopText(1) + this.shift_y;

      ctx.save();

      if (name) {
        ctx.setFont(font.family, font.size, font.weight);
        ctx.fillText(name, x, y);
        x += ctx.measureText(name).width;
      }

      if (duration && bpm) {
        ctx.setFont(font.family, font.size, 'normal');

        if (name) {
          x += ctx.measureText(" ").width;
          ctx.fillText("(", x, y);
          x += ctx.measureText("(").width;
        }

        var code = Vex.Flow.durationToGlyph(duration);

        x += 3 * scale;
        Vex.Flow.renderGlyph(ctx, x, y, options.glyph_font_scale, code.code_head);
        x += code.head_width * scale;

        // Draw stem and flags
        if (code.stem) {
          var stem_height = 30;

          if (code.beam_count) stem_height += 3 * (code.beam_count - 1);

          stem_height *= scale;

          var y_top = y - stem_height;
          ctx.fillRect(x, y_top, scale, stem_height);

          if (code.flag) {
            Vex.Flow.renderGlyph(ctx, x + scale, y_top, options.glyph_font_scale,
                                 code.code_flag_upstem);

            if (!dots) x += 6 * scale;
          }
        }

        // Draw dot
        for (var i = 0; i < dots; i++) {
          x += 6 * scale;
          ctx.beginPath();
          ctx.arc(x, y + 2 * scale, 2 * scale, 0, Math.PI * 2, false);
          ctx.fill();
        }

        ctx.fillText(" = " + bpm + (name ? ")" : ""), x + 3 * scale, y);
      }

      ctx.restore();
      return this;
    }
  });

  return StaveTempo;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// Author Taehoon Moon 2014

/**
 * @constructor
 */
Vex.Flow.StaveText = (function() {
  function StaveText(text, position, options) {
    if (arguments.length > 0) this.init(text, position, options);
  }

  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(StaveText, Modifier, {
    init: function(text, position, options) {
      StaveText.superclass.init.call(this);

      this.setWidth(16);
      this.text = text;
      this.position = position;
      this.options = {
        shift_x: 0,
        shift_y: 0,
        justification: Vex.Flow.TextNote.Justification.CENTER
      };
      Vex.Merge(this.options, options);

      this.font = {
        family: "times",
        size: 16,
        weight: "normal"
      };
    },

    getCategory: function() { return "stavetext"; },
    setStaveText: function(text) { this.text = text; return this; },
    setShiftX: function(x) { this.shift_x = x; return this; },
    setShiftY: function(y) { this.shift_y = y; return this; },

    setFont: function(font) {
      Vex.Merge(this.font, font);
    },

    setText: function(text) {
      this.text = text;
    },

    draw: function(stave) {
      if (!stave.context) throw new Vex.RERR("NoContext",
        "Can't draw stave text without a context.");

      var ctx = stave.context;

      ctx.save();
      ctx.lineWidth = 2;
      ctx.setFont(this.font.family, this.font.size, this.font.weight);
      var text_width = ctx.measureText("" + this.text).width;

      var x, y;
      var Modifier = Vex.Flow.Modifier;
      switch(this.position) {
        case Modifier.Position.LEFT:
        case Modifier.Position.RIGHT:
          y = (stave.getYForLine(0) + stave.getBottomLineY()) / 2 + this.options.shift_y;
          if(this.position == Modifier.Position.LEFT) {
            x = stave.getX() - text_width - 24 + this.options.shift_x;
          }
          else {
            x = stave.getX() + stave.getWidth() + 24 + this.options.shift_x;
          }
          break;
        case Modifier.Position.ABOVE:
        case Modifier.Position.BELOW:
          var Justification = Vex.Flow.TextNote.Justification;
          x = stave.getX() + this.options.shift_x;
          if(this.options.justification == Justification.CENTER) {
            x += stave.getWidth() / 2 - text_width / 2;
          }
          else if(this.options.justification == Justification.RIGHT) {
            x += stave.getWidth() - text_width;
          }
          
          if(this.position == Modifier.Position.ABOVE) {
            y = stave.getYForTopText(2) + this.options.shift_y;
          }
          else {
            y = stave.getYForBottomText(2) + this.options.shift_y;
          }
          break;
        default:
          throw new Vex.RERR("InvalidPosition",
            "Value Must be in Modifier.Position.");
      }

      ctx.fillText("" + this.text, x, y + 4);
      ctx.restore();
      return this;
    }
  });

  return StaveText;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// A `BarNote` is used to render bar lines (from `barline.js`). `BarNote`s can
// be added to a voice and rendered in the middle of a stave. Since it has no
// duration, it consumes no `tick`s, and is dealt with appropriately by the formatter.
//
// See `tests/barnote_tests.js` for usage examples.

Vex.Flow.BarNote = (function() {
  function BarNote() { this.init(); }

  // To enable logging for this class. Set `Vex.Flow.BarNote.DEBUG` to `true`.
  function L() { if (BarNote.DEBUG) Vex.L("Vex.Flow.BarNote", arguments); }

  // ## Prototype Methods
  Vex.Inherit(BarNote, Vex.Flow.Note, {
    init: function() {
      BarNote.superclass.init.call(this, {duration: "b"});

      var TYPE = Vex.Flow.Barline.type;
      this.metrics = {
        widths: {}
      };

      // Defined this way to prevent lint errors.
      this.metrics.widths[TYPE.SINGLE] = 8;
      this.metrics.widths[TYPE.DOUBLE] = 12;
      this.metrics.widths[TYPE.END] = 15;
      this.metrics.widths[TYPE.REPEAT_BEGIN] = 14;
      this.metrics.widths[TYPE.REPEAT_END] = 14;
      this.metrics.widths[TYPE.REPEAT_BOTH] = 18;
      this.metrics.widths[TYPE.NONE] = 0;

      // Tell the formatter that bar notes have no duration.
      this.ignore_ticks = true;
      this.type = TYPE.SINGLE;

      // Set width to width of relevant `Barline`.
      this.setWidth(this.metrics.widths[this.type]);
    },

    // Get and set the type of Bar note. `type` must be one of `Vex.Flow.Barline.type`.
    getType: function() { return this.type; },
    setType: function(type) {
      this.type = type;
      this.setWidth(this.metrics.widths[this.type]);
      return this;
    },

    getBoundingBox: function() {
      return new Vex.Flow.BoundingBox(0, 0, 0, 0);
    },

    addToModifierContext: function() {
      /* overridden to ignore */
      return this;
    },

    preFormat: function() {
      /* overridden to ignore */
      this.setPreFormatted(true);
      return this;
    },

    // Render note to stave.
    draw: function() {
      if (!this.stave) throw new Vex.RERR("NoStave", "Can't draw without a stave.");
      L("Rendering bar line at: ", this.getAbsoluteX());
      var barline = new Vex.Flow.Barline(this.type, this.getAbsoluteX());
      barline.draw(this.stave);
    }
  });

  return BarNote;
}());
// VexFlow - Music Engraving for HTML5
// Author: Mike Corrigan <corrigan@gmail.com>
//
// This class implements tremolo notation.

/**
 * @constructor
 */
Vex.Flow.Tremolo = (function() {
  function Tremolo(num) {
    if (arguments.length > 0) this.init(num);
  }

  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(Tremolo, Modifier, {
    init: function(num) {
      Tremolo.superclass.init.call(this);

      this.num = num;
      this.note = null;
      this.index = null;
      this.position = Modifier.Position.CENTER;
      this.code = "v74";
      this.shift_right = -2;
      this.y_spacing = 4;

      this.render_options = {
        font_scale: 35,
        stroke_px: 3,
        stroke_spacing: 10
      };

      this.font = {
        family: "Arial",
        size: 16,
        weight: ""
      };
    },

    getCategory: function() { return "tremolo"; },

    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw Tremolo without a context.");
      if (!(this.note && (this.index != null))) throw new Vex.RERR("NoAttachedNote",
        "Can't draw Tremolo without a note and index.");

      var start = this.note.getModifierStartXY(this.position, this.index);
      var x = start.x;
      var y = start.y;

      x += this.shift_right;
      for (var i = 0; i < this.num; ++i) {
        Vex.Flow.renderGlyph(this.context, x, y,
                             this.render_options.font_scale, this.code);
        y += this.y_spacing;
      }
    }
  });

  return Tremolo;
}());
/**
 * Create a new tuplet from the specified notes. The notes must
 * be part of the same line, and have the same duration (in ticks).
 *
 * @constructor
 * @param {Array.<Vex.Flow.StaveNote>} A set of notes.
 */
Vex.Flow.Tuplet = (function() {
  function Tuplet(notes, options) {
    if (arguments.length > 0) this.init(notes, options);
  }

  Tuplet.LOCATION_TOP = 1;
  Tuplet.LOCATION_BOTTOM = -1;

  Tuplet.prototype = {
    init: function(notes, options) {
      if (!notes || notes == []) {
        throw new Vex.RuntimeError("BadArguments", "No notes provided for tuplet.");
      }

      if (notes.length == 1) {
        throw new Vex.RuntimeError("BadArguments", "Too few notes for tuplet.");
      }

      this.options = Vex.Merge({}, options);
      this.notes = notes;
      this.num_notes = 'num_notes' in this.options ?
        this.options.num_notes : notes.length;
      this.beats_occupied = 'beats_occupied' in this.options ?
        this.options.beats_occupied : 2;
      this.bracketed = (notes[0].beam == null);
      this.ratioed = false;
      this.point = 28;
      this.y_pos = 16;
      this.x_pos = 100;
      this.width = 200;
      this.location = Tuplet.LOCATION_TOP;

      Vex.Flow.Formatter.AlignRestsToNotes(notes, true, true);
      this.resolveGlyphs();
      this.attach();
    },

    attach: function () {
      for (var i = 0; i < this.notes.length; i++) {
        var note = this.notes[i];
        note.setTuplet(this);
      }
    },

    detach: function () {
      for (var i = 0; i < this.notes.length; i++) {
        var note = this.notes[i];
        note.setTuplet(null);
      }
    },

    setContext: function(context) {
      this.context = context;
      return this;
    },

    /**
     * Set whether or not the bracket is drawn.
     */
    setBracketed: function(bracketed) {
      this.bracketed = bracketed ? true : false;
      return this;
    },

    /**
     * Set whether or not the ratio is shown.
     */
    setRatioed: function(ratioed) {
      this.ratioed = ratioed ? true : false;
      return this;
    },

    /**
     * Set the tuplet to be displayed either on the top or bottom of the stave
     */
    setTupletLocation: function(location) {
      if (!location) location = Tuplet.LOCATION_TOP;
      else if (location != Tuplet.LOCATION_TOP &&
          location != Tuplet.LOCATION_BOTTOM) {
        throw new Vex.RERR("BadArgument", "Invalid tuplet location: " + location);
      }

      this.location = location;
      return this;
    },

    getNotes: function() {
      return this.notes;
    },

    getNoteCount: function() {
      return this.num_notes;
    },

    getBeatsOccupied: function() {
      return this.beats_occupied;
    },

    setBeatsOccupied: function(beats) {
      this.detach();
      this.beats_occupied = beats;
      this.resolveGlyphs();
      this.attach();
    },

    resolveGlyphs: function() {
      this.num_glyphs = [];
      var n = this.num_notes;
      while (n >= 1) {
        this.num_glyphs.push(new Vex.Flow.Glyph("v" + (n % 10), this.point));
        n = parseInt(n / 10, 10);
      }

      this.denom_glyphs = [];
      n = this.beats_occupied;
      while (n >= 1) {
        this.denom_glyphs.push(new Vex.Flow.Glyph("v" + (n % 10), this.point));
        n = parseInt(n / 10, 10);
      }
    },

    draw: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");

      // determine x value of left bound of tuplet
      var first_note = this.notes[0];
      var last_note = this.notes[this.notes.length - 1];

      if (!this.bracketed) {
        this.x_pos = first_note.getStemX();
        this.width = last_note.getStemX() - this.x_pos;
      }
      else {
        this.x_pos = first_note.getTieLeftX() - 5;
        this.width = last_note.getTieRightX() - this.x_pos + 5;
      }

      // determine y value for tuplet
      var i;
      if (this.location == Tuplet.LOCATION_TOP) {
        this.y_pos = first_note.getStave().getYForLine(0) - 15;
        //this.y_pos = first_note.getStemExtents().topY - 10;

        for (i=0; i<this.notes.length; ++i) {
          var top_y = this.notes[i].getStemExtents().topY - 10;
          if (top_y < this.y_pos)
            this.y_pos = top_y;
        }
      }
      else {
        this.y_pos = first_note.getStave().getYForLine(4) + 20;

        for (i=0; i<this.notes.length; ++i) {
          var bottom_y = this.notes[i].getStemExtents().topY + 10;
          if (bottom_y > this.y_pos)
            this.y_pos = bottom_y;
        }
      }

      // calculate total width of tuplet notation
      var width = 0;
      var glyph;
      for (glyph in this.num_glyphs) {
        width += this.num_glyphs[glyph].getMetrics().width;
      }
      if (this.ratioed) {
        for (glyph in this.denom_glyphs) {
          width += this.denom_glyphs[glyph].getMetrics().width;
        }
        width += this.point * 0.32;
      }

      var notation_center_x = this.x_pos + (this.width/2);
      var notation_start_x = notation_center_x - (width/2);

      // draw bracket if the tuplet is not beamed
      if (this.bracketed) {
        var line_width = this.width/2 - width/2 - 5;

        // only draw the bracket if it has positive length
        if (line_width > 0) {
          this.context.fillRect(this.x_pos, this.y_pos,line_width, 1);
          this.context.fillRect(this.x_pos + this.width / 2 + width / 2 + 5,
                                this.y_pos,line_width, 1);
          this.context.fillRect(this.x_pos,
              this.y_pos + (this.location == Tuplet.LOCATION_BOTTOM),
              1, this.location * 10);
          this.context.fillRect(this.x_pos + this.width,
              this.y_pos + (this.location == Tuplet.LOCATION_BOTTOM),
              1, this.location * 10);
        }
      }

      // draw numerator glyphs
      var x_offset = 0;
      var size = this.num_glyphs.length;
      for (glyph in this.num_glyphs) {
        this.num_glyphs[size-glyph-1].render(
            this.context, notation_start_x + x_offset,
            this.y_pos + (this.point/3) - 2);
        x_offset += this.num_glyphs[size-glyph-1].getMetrics().width;
      }

      // display colon and denominator if the ratio is to be shown
      if (this.ratioed) {
        var colon_x = notation_start_x + x_offset + this.point*0.16;
        var colon_radius = this.point * 0.06;
        this.context.beginPath();
        this.context.arc(colon_x, this.y_pos - this.point*0.08,
                         colon_radius, 0, Math.PI*2, true);
        this.context.closePath();
        this.context.fill();
        this.context.beginPath();
        this.context.arc(colon_x, this.y_pos + this.point*0.12,
                         colon_radius, 0, Math.PI*2, true);
        this.context.closePath();
        this.context.fill();
        x_offset += this.point*0.32;
        size = this.denom_glyphs.length;
        for (glyph in this.denom_glyphs) {
          this.denom_glyphs[size-glyph-1].render(
              this.context, notation_start_x + x_offset,
              this.y_pos + (this.point/3) - 2);
          x_offset += this.denom_glyphs[size-glyph-1].getMetrics().width;
        }
      }
    }
  };

  return Tuplet;
}());
// Vex Music Notation
// Mohit Muthanna <mohit@muthanna.com>
//
// Copyright Mohit Muthanna 2010

// Bounding boxes for interactive notation

/** @constructor */
Vex.Flow.BoundingBox = (function() {
  function BoundingBox(x, y, w, h) { this.init(x, y, w, h); }
  BoundingBox.copy = function(that) {
    return new BoundingBox(that.x, that.y, that.w, that.h); };

  BoundingBox.prototype = {
    init: function(x, y, w, h) {
      this.x = x;
      this.y = y;
      this.w = w;
      this.h = h;
    },

    getX: function() { return this.x; },
    getY: function() { return this.y; },
    getW: function() { return this.w; },
    getH: function() { return this.h; },

    setX: function(x) { this.x = x; return this; },
    setY: function(y) { this.y = y; return this; },
    setW: function(w) { this.w = w; return this; },
    setH: function(h) { this.h = h; return this; },

    move: function(x, y) { this.x += x; this.y += y; },
    clone: function() { return BoundingBox.copy(this); },

    // Merge my box with given box. Creates a bigger bounding box unless
    // the given box is contained in this one.
    mergeWith: function(boundingBox, ctx) {
      var that = boundingBox;

      var new_x = this.x < that.x ? this.x : that.x;
      var new_y = this.y < that.y ? this.y : that.y;
      var new_w = (this.x + this.w) < (that.x + that.w) ? (that.x + that.w) - this.x : (this.x + this.w) - Vex.Min(this.x, that.x);
      var new_h = (this.y + this.h) < (that.y + that.h) ? (that.y + that.h) - this.y : (this.y + this.h) - Vex.Min(this.y, that.y);

      this.x = new_x;
      this.y = new_y;
      this.w = new_w;
      this.h = new_h;

      if (ctx) this.draw(ctx);
      return this;
    },

    draw: function(ctx, x, y) {
      if (!x) x = 0;
      if (!y) y = 0;
      ctx.rect(this.x + x, this.y + y, this.w, this.h);
      ctx.stroke();
    }
  };

  return BoundingBox;
}());// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// `TextNote` is a notation element that is positioned in time. Generally 
// meant for objects that sit above/below the staff and inline with each other.
// Examples of this would be such as dynamics, lyrics, chord changes, etc.
Vex.Flow.TextNote = (function() {
  function TextNote(text_struct) {
    if (arguments.length > 0) this.init(text_struct);
  }

  TextNote.Justification = {
    LEFT: 1,
    CENTER: 2,
    RIGHT: 3
  };

  // Glyph data
  TextNote.GLYPHS = {
    "segno": {
      code: "v8c",
      point: 40,
      x_shift: 0,
      y_shift: -10
      // width: 10 // optional
    },
    "tr": {
      code: "v1f",
      point: 40,
      x_shift: 0,
      y_shift: 0
      // width: 10 // optional
    },
    "mordent_upper": {
      code: "v1e",
      point: 40,
      x_shift: 0,
      y_shift: 0
      // width: 10 // optional
    },
    "mordent_lower": {
      code: "v45",
      point: 40,
      x_shift: 0,
      y_shift: 0
      // width: 10 // optional
    },
    "f": {
      code: "vba",
      point: 40,
      x_shift: 0,
      y_shift: 0
      // width: 10 // optional
    },
    "p": {
      code: "vbf",
      point: 40,
      x_shift: 0,
      y_shift: 0
      // width: 10 // optional
    },
    "m": {
      code: "v62",
      point: 40,
      x_shift: 0,
      y_shift: 0
      // width: 10 // optional
    },
    "s": {
      code: "v4a",
      point: 40,
      x_shift: 0,
      y_shift: 0
      // width: 10 // optional
    },
    "z": {
      code: "v80",
      point: 40,
      x_shift: 0,
      y_shift: 0
      // width: 10 // optional
    },
    "coda": {
      code: "v4d",
      point: 40,
      x_shift: 0,
      y_shift: -8
      // width: 10 // optional
    },
    "pedal_open": {
      code: "v36",
      point:40,
      x_shift:0,
      y_shift:0
    },
    "pedal_close": {
      code: "v5d",
      point:40,
      x_shift:0,
      y_shift:3
    },
    "caesura_straight": {
      code: "v34",
      point:40,
      x_shift:0,
      y_shift:2
    },
    "caesura_curved": {
      code: "v4b",
      point:40,
      x_shift:0,
      y_shift:2
    },
    "breath": {
      code: "v6c",
      point:40,
      x_shift:0,
      y_shift:0
    },
    "tick": {
      code: "v6f",
      point:50,
      x_shift:0,
      y_shift:0
    },
    "turn": {
      code: "v72",
      point:40,
      x_shift:0,
      y_shift:0
    },
    "turn_inverted": {
      code: "v33",
      point:40,
      x_shift:0,
      y_shift:0
    },

    // DEPRECATED - please use "mordent_upper" or "mordent_lower"
    "mordent": {
      code: "v1e",
      point: 40,
      x_shift: 0,
      y_shift: 0
      // width: 10 // optional
    },
  };

  // ## Prototype Methods
  Vex.Inherit(TextNote, Vex.Flow.Note, {
    init: function(text_struct) {
      TextNote.superclass.init.call(this, text_struct);

      // Note properties
      this.text = text_struct.text;
      this.superscript = text_struct.superscript;
      this.subscript = text_struct.subscript;
      this.glyph_type = text_struct.glyph;
      this.glyph = null;
      this.font = {
        family: "Arial",
        size: 12,
        weight: ""
      };

      // Set font
      if (text_struct.font) this.font = text_struct.font;

      // Determine and set initial note width. Note that the text width is 
      // an approximation and isn't very accurate. The only way to accurately
      // measure the length of text is with `canvasContext.measureText()`
      if (this.glyph_type) {
        var struct = TextNote.GLYPHS[this.glyph_type];
        if (!struct) throw new Vex.RERR("Invalid glyph type: " + this.glyph_type);

        this.glyph = new Vex.Flow.Glyph(struct.code, struct.point, {cache: false});

        if (struct.width)
          this.setWidth(struct.width);
        else
          this.setWidth(this.glyph.getMetrics().width);

        this.glyph_struct = struct;
      } else {
        this.setWidth(Vex.Flow.textWidth(this.text));
      }
      this.line = text_struct.line || 0;
      this.smooth = text_struct.smooth || false;
      this.ignore_ticks = text_struct.ignore_ticks || false;
      this.justification = TextNote.Justification.LEFT;
    },

    // Set the horizontal justification of the TextNote
    setJustification: function(just) {
      this.justification = just;
      return this;
    },

    // Set the Stave line on which the note should be placed
    setLine: function(line) {
      this.line = line;
      return this;
    },

    // Pre-render formatting
    preFormat: function() {
      if (!this.context) throw new Vex.RERR("NoRenderContext",
          "Can't measure text without rendering context.");
      if (this.preFormatted) return;

      if (this.smooth) {
        this.setWidth(0);
      } else {
        if (this.glyph) {
          // Width already set.
        } else {
          this.setWidth(this.context.measureText(this.text).width);
        }
      }

      if (this.justification == TextNote.Justification.CENTER) {
        this.extraLeftPx = this.width / 2;
      } else if (this.justification == TextNote.Justification.RIGHT) {
        this.extraLeftPx = this.width;
      }

      this.setPreFormatted(true);
    },

    // Renders the TextNote
    draw: function() {
      if (!this.context) throw new Vex.RERR("NoCanvasContext",
          "Can't draw without a canvas context.");
      if (!this.stave) throw new Vex.RERR("NoStave", "Can't draw without a stave.");

      var ctx = this.context;
      var x = this.getAbsoluteX();
      if (this.justification == TextNote.Justification.CENTER) {
        x -= this.getWidth() / 2;
      } else if (this.justification == TextNote.Justification.RIGHT) {
        x -= this.getWidth();
      }

      var y;
      if (this.glyph) {
        y = this.stave.getYForLine(this.line + (-3));
        this.glyph.render(this.context,
                          x + this.glyph_struct.x_shift,
                          y + this.glyph_struct.y_shift);
      } else {
        y = this.stave.getYForLine(this.line + (-3));
        ctx.save();
        ctx.setFont(this.font.family, this.font.size, this.font.weight);
        ctx.fillText(this.text, x, y);

        // Width of the letter M gives us the approximate height of the text
        var height = ctx.measureText("M").width;
        // Get accurate width of text
        var width = ctx.measureText(this.text).width;

        // Write superscript
        if (this.superscript) {
          ctx.setFont(this.font.family, this.font.size / 1.3, this.font.weight);
          ctx.fillText(this.superscript, x + width + 2, y - (height/2.2));
        }

        // Write subscript
        if (this.subscript) {
          ctx.setFont(this.font.family, this.font.size / 1.3, this.font.weight);
          ctx.fillText(this.subscript, x + width + 2, y + (height/2.2) - 1);
        }

        ctx.restore();
      }
    }
  });

  return TextNote;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
// Author Larry Kuhns 2013
// Class to draws string numbers into the notation.

/**
 * @constructor
 */
Vex.Flow.FretHandFinger = (function() {
  function FretHandFinger(number) {
    if (arguments.length > 0) this.init(number);
  }

  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(FretHandFinger, Modifier, {
    init: function(number) {
      var superclass = Vex.Flow.FretHandFinger.superclass;
      superclass.init.call(this);

      this.note = null;
      this.index = null;
      this.finger = number;
      this.width = 7;
      this.position = Modifier.Position.LEFT;  // Default position above stem or note head
      this.x_shift = 0;
      this.y_shift = 0;
      this.x_offset = 0;       // Horizontal offset from default
      this.y_offset = 0;       // Vertical offset from default
      this.font = {
        family: "sans-serif",
        size: 9,
        weight: "bold"
      };
    },

    getCategory: function() { return "frethandfinger"; },
    getNote: function() { return this.note; },
    setNote: function(note) { this.note = note; return this; },
    getIndex: function() { return this.index; },
    setIndex: function(index) { this.index = index; return this; },
    getPosition: function() { return this.position; },
    setPosition: function(position) {
      if (position >= Modifier.Position.LEFT &&
          position <= Modifier.Position.BELOW)
        this.position = position;
      return this;
    },
    setFretHandFinger: function(number) { this.finger = number; return this; },
    setOffsetX: function(x) { this.x_offset = x; return this; },
    setOffsetY: function(y) { this.y_offset = y; return this; },

    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw string number without a context.");
      if (!(this.note && (this.index != null))) throw new Vex.RERR("NoAttachedNote",
        "Can't draw string number without a note and index.");

      var ctx = this.context;
      var start = this.note.getModifierStartXY(this.position, this.index);
      var dot_x = (start.x + this.x_shift + this.x_offset);
      var dot_y = start.y + this.y_shift + this.y_offset + 5;

      switch (this.position) {
        case Modifier.Position.ABOVE:
          dot_x -= 4;
          dot_y -= 12;
          break;
        case Modifier.Position.BELOW:
          dot_x -= 2;
          dot_y += 10;
          break;
        case Modifier.Position.LEFT:
          dot_x -= this.width;
          break;
        case Modifier.Position.RIGHT:
          dot_x += 1;
          break;
      }

      ctx.save();
      ctx.setFont(this.font.family, this.font.size, this.font.weight);
      ctx.fillText("" + this.finger, dot_x, dot_y);

      ctx.restore();
    }
  });

  return FretHandFinger;
}());// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
// Author Larry Kuhns 2013
// Class to draws string numbers into the notation.

Vex.Flow.StringNumber = (function() {
  function StringNumber(number) {
    if (arguments.length > 0) this.init(number);
  }

  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(StringNumber, Modifier, {
    init: function(number) {
      StringNumber.superclass.init.call(this);

      this.note = null;
      this.last_note = null;
      this.index = null;
      this.string_number = number;
      this.setWidth(20);                                 // ???
      this.position = Modifier.Position.ABOVE;  // Default position above stem or note head
      this.x_shift = 0;
      this.y_shift = 0;
      this.x_offset = 0;                               // Horizontal offset from default
      this.y_offset = 0;                               // Vertical offset from default
      this.dashed = true;                              // true - draw dashed extension  false - no extension
      this.leg = Vex.Flow.Renderer.LineEndType.NONE;   // draw upward/downward leg at the of extension line
      this.radius = 8;
      this.font = {
        family: "sans-serif",
        size: 10,
        weight: "bold"
      };
    },

    getCategory: function() { return "stringnumber"; },
    getNote: function() { return this.note; },
    setNote: function(note) { this.note = note; return this; },
    getIndex: function() { return this.index; },
    setIndex: function(index) { this.index = index; return this; },

    setLineEndType: function(leg) {
      if (leg >= Vex.Flow.Renderer.LineEndType.NONE &&
          leg <= Vex.Flow.Renderer.LineEndType.DOWN)
        this.leg = leg;
      return this;
    },

    getPosition: function() { return this.position; },
    setPosition: function(position) {
      if (position >= Modifier.Position.LEFT &&
          position <= Modifier.Position.BELOW)
        this.position = position;
      return this;
    },

    setStringNumber: function(number) { this.string_number = number; return this; },
    setOffsetX: function(x) { this.x_offset = x; return this; },
    setOffsetY: function(y) { this.y_offset = y; return this; },
    setLastNote: function(note) { this.last_note = note; return this; },
    setDashed: function(dashed) { this.dashed = dashed; return this; },

    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw string number without a context.");
      if (!(this.note && (this.index != null))) throw new Vex.RERR("NoAttachedNote",
        "Can't draw string number without a note and index.");

      var ctx = this.context;
      var line_space = this.note.stave.options.spacing_between_lines_px;

      var start = this.note.getModifierStartXY(this.position, this.index);
      var dot_x = (start.x + this.x_shift + this.x_offset);
      var dot_y = start.y + this.y_shift + this.y_offset;

      switch (this.position) {
        case Modifier.Position.ABOVE:
        case Modifier.Position.BELOW:
          var stem_ext = this.note.getStemExtents();
          var top = stem_ext.topY;
          var bottom = stem_ext.baseY + 2;

          if (this.note.stem_direction == Vex.Flow.StaveNote.STEM_DOWN) {
            top = stem_ext.baseY;
            bottom = stem_ext.topY - 2;
          }

          if (this.position == Modifier.Position.ABOVE) {
            dot_y = this.note.hasStem() ? top - (line_space * 1.75)
                                        : start.y - (line_space * 1.75);
        } else {
            dot_y = this.note.hasStem() ? bottom + (line_space * 1.5)
                                        : start.y + (line_space * 1.75);
          }

          dot_y += this.y_shift + this.y_offset;

          break;
        case Modifier.Position.LEFT:
          dot_x -= (this.radius / 2) + 5;
          break;
        case Modifier.Position.RIGHT:
          dot_x += (this.radius / 2) + 6;
          break;
      }

      ctx.save();
      ctx.beginPath();
      ctx.arc(dot_x, dot_y, this.radius, 0, Math.PI * 2, false);
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setFont(this.font.family, this.font.size, this.font.weight);
      var x = dot_x - ctx.measureText(this.string_number).width / 2;
      ctx.fillText("" + this.string_number, x, dot_y + 4.5);

      if (this.last_note != null) {
        var end = this.last_note.getStemX() - this.note.getX() + 5;
        ctx.strokeStyle="#000000";
        ctx.lineCap = "round";
        ctx.lineWidth = 0.6;
        if (this.dashed)
          Vex.Flow.Renderer.drawDashedLine(ctx, dot_x + 10, dot_y, dot_x + end, dot_y, [3,3]);
        else
          Vex.Flow.Renderer.drawDashedLine(ctx, dot_x + 10, dot_y, dot_x + end, dot_y, [3,0]);

        var len, pattern;
        switch (this.leg) {
          case Vex.Flow.Renderer.LineEndType.UP:
            len = -10;
            pattern = this.dashed ? [3,3] : [3,0];
            Vex.Flow.Renderer.drawDashedLine(ctx, dot_x + end, dot_y, dot_x + end, dot_y + len, pattern);
            break;
          case Vex.Flow.Renderer.LineEndType.DOWN:
            len = 10;
            pattern = this.dashed ? [3,3] : [3,0];
            Vex.Flow.Renderer.drawDashedLine(ctx, dot_x + end, dot_y, dot_x + end, dot_y + len, pattern);
            break;
        }
      }

      ctx.restore();
    }
  });

  return StringNumber;
}());
// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
// Author Larry Kuhns 2013
// Class implements chord strokes - arpeggiated, brush & rasquedo.

Vex.Flow.Stroke = (function() {
  function Stroke(type, options) {
    if (arguments.length > 0) this.init(type, options);
  }

  Stroke.Type = {
    BRUSH_DOWN: 1,
    BRUSH_UP: 2,
    ROLL_DOWN: 3,        // Arpegiated chord
    ROLL_UP: 4,          // Arpegiated chord
    RASQUEDO_DOWN: 5,
    RASQUEDO_UP: 6
  };

  var Modifier = Vex.Flow.Modifier;
  Vex.Inherit(Stroke, Modifier, {
    init: function(type, options) {
      Stroke.superclass.init.call(this);

      this.note = null;
      this.options = Vex.Merge({}, options);

      // multi voice - span stroke across all voices if true
      this.all_voices = 'all_voices' in this.options ?
        this.options.all_voices : true;

      // multi voice - end note of stroke, set in draw()
      this.note_end = null;
      this.index = null;
      this.type = type;
      this.position = Modifier.Position.LEFT;

      this.render_options = {
        font_scale: 38,
        stroke_px: 3,
        stroke_spacing: 10
      };

      this.font = {
       family: "serif",
       size: 10,
       weight: "bold italic"
     };

      this.setXShift(0);
      this.setWidth(10);
    },

    getCategory: function() { return "strokes"; },
    getPosition: function() { return this.position; },
    addEndNote: function(note) { this.note_end = note; return this; },

    draw: function() {
      if (!this.context) throw new Vex.RERR("NoContext",
        "Can't draw stroke without a context.");
      if (!(this.note && (this.index != null))) throw new Vex.RERR("NoAttachedNote",
        "Can't draw stroke without a note and index.");
      var start = this.note.getModifierStartXY(this.position, this.index);
      var ys = this.note.getYs();
      var topY = start.y;
      var botY = start.y;
      var x = start.x - 5;
      var line_space = this.note.stave.options.spacing_between_lines_px;

      var notes = this.getModifierContext().getModifiers(this.note.getCategory());
      var i;
      for (i = 0; i < notes.length; i++) {
        ys = notes[i].getYs();
        for (var n = 0; n < ys.length; n++) {
          if (this.note == notes[i] || this.all_voices) {
            topY = Vex.Min(topY, ys[n]);
            botY = Vex.Max(botY, ys[n]);
          }
        }
      }

      var arrow, arrow_shift_x, arrow_y, text_shift_x, text_y;
      switch (this.type) {
        case Stroke.Type.BRUSH_DOWN:
          arrow = "vc3";
          arrow_shift_x = -3;
          arrow_y = topY - (line_space / 2) + 10;
          botY += (line_space / 2);
          break;
        case Stroke.Type.BRUSH_UP:
          arrow = "v11";
          arrow_shift_x = 0.5;
          arrow_y = botY + (line_space / 2);
          topY -= (line_space / 2);
          break;
        case Stroke.Type.ROLL_DOWN:
        case Stroke.Type.RASQUEDO_DOWN:
          arrow = "vc3";
          arrow_shift_x = -3;
          text_shift_x = this.x_shift + arrow_shift_x - 2;
          if (this.note instanceof Vex.Flow.StaveNote) {
            topY += 1.5 * line_space;
            if ((botY - topY) % 2 !== 0) {
              botY += 0.5 * line_space;
            } else {
              botY += line_space;
            }
            arrow_y = topY - line_space;
            text_y = botY + line_space + 2;
          } else {
            topY += 1.5 * line_space;
            botY += line_space;
            arrow_y = topY - 0.75 * line_space;
            text_y = botY + 0.25 * line_space;
          }
          break;
        case Stroke.Type.ROLL_UP:
        case Stroke.Type.RASQUEDO_UP:
          arrow = "v52";
          arrow_shift_x = -4;
          text_shift_x = this.x_shift + arrow_shift_x - 1;
          if (this.note instanceof Vex.Flow.StaveNote) {
            arrow_y = line_space / 2;
            topY += 0.5 * line_space;
            if ((botY - topY) % 2 === 0) {
              botY += line_space / 2;
            }
            arrow_y = botY + 0.5 * line_space;
            text_y = topY - 1.25 * line_space;
          } else {
            topY += 0.25 * line_space;
            botY += 0.5 * line_space;
            arrow_y = botY + 0.25 * line_space;
            text_y = topY - line_space;
          }
          break;
      }

      // Draw the stroke
      if (this.type == Stroke.Type.BRUSH_DOWN ||
          this.type == Stroke.Type.BRUSH_UP) {
        this.context.fillRect(x + this.x_shift, topY, 1, botY - topY);
      } else {
        if (this.note instanceof Vex.Flow.StaveNote) {
          for (i = topY; i <= botY; i += line_space) {
            Vex.Flow.renderGlyph(this.context, x + this.x_shift - 4,
                                 i,
                                 this.render_options.font_scale, "va3");
          }
        } else {
          for (i = topY; i <= botY; i+= 10) {
            Vex.Flow.renderGlyph(this.context, x + this.x_shift - 4,
                                 i,
                                 this.render_options.font_scale, "va3");
          }
          if (this.type == Vex.Flow.Stroke.Type.RASQUEDO_DOWN)
            text_y = i + 0.25 * line_space;
        }
      }

      // Draw the arrow head
      Vex.Flow.renderGlyph(this.context, x + this.x_shift + arrow_shift_x, arrow_y,
                           this.render_options.font_scale, arrow);

      // Draw the rasquedo "R"
      if (this.type == Stroke.Type.RASQUEDO_DOWN ||
          this.type == Stroke.Type.RASQUEDO_UP) {
        this.context.save();
        this.context.setFont(this.font.family, this.font.size, this.font.weight);
        this.context.fillText("R", x + text_shift_x, text_y);
        this.context.restore();
      }
    }
  });

  return Stroke;
}());// VexFlow - Music Engraving for HTML5
// Copyright Mohit Muthanna 2010
//
// This class implements curves (for slurs)

Vex.Flow.Curve = (function() {
  // from: Start note
  // to: End note
  // options:
  //    cps: List of control points
  //    x_shift: pixels to shift
  //    y_shift: pixels to shift
  function Curve(from, to, options) {
    if (arguments.length > 0) this.init(from, to, options);
  }

  Curve.Position = {
    NEAR_HEAD: 1,
    NEAR_TOP: 2
  };

  Curve.DEBUG = true;

  Curve.prototype = {
    init: function(from, to, options) {
      this.render_options = {
        spacing: 2,
        thickness: 2,
        x_shift: 0,
        y_shift: 10,
        position: Curve.Position.NEAR_HEAD,
        invert: false,
        cps: [{x: 0, y: 10}, {x: 0, y: 10}]
      };

      Vex.Merge(this.render_options, options);
      this.setNotes(from, to);
    },

    setContext: function(context) { this.context = context; return this; },
    setNotes: function(from, to) {
      if (!from && !to)
        throw new Vex.RuntimeError("BadArguments",
            "Curve needs to have either first_note or last_note set.");

      this.from = from;
      this.to = to;
      return this;
    },

    /**
     * @return {boolean} Returns true if this is a partial bar.
     */
    isPartial: function() {
      return (!this.from || !this.to);
    },

    renderCurve: function(params) {
      var ctx = this.context;
      var cps = this.render_options.cps;

      var x_shift = this.render_options.x_shift;
      var y_shift = this.render_options.y_shift * params.direction;

      var first_x = params.first_x + x_shift;
      var first_y = params.first_y + y_shift;
      var last_x = params.last_x - x_shift;
      var last_y = params.last_y + y_shift;
      var thickness = this.render_options.thickness;

      var cp_spacing = (last_x - first_x) / (cps.length + 2);

      ctx.beginPath();
      ctx.moveTo(first_x, first_y);
      ctx.bezierCurveTo(first_x + cp_spacing + cps[0].x,
                        first_y + (cps[0].y * params.direction),
                        last_x - cp_spacing + cps[1].x,
                        last_y + (cps[1].y * params.direction),
                        last_x, last_y);
      ctx.bezierCurveTo(last_x - cp_spacing + cps[1].x,
                        last_y + ((cps[1].y + thickness) * params.direction),
                        first_x + cp_spacing + cps[0].x,
                        first_y + ((cps[0].y + thickness) * params.direction),
                        first_x, first_y);
      ctx.stroke();
      ctx.closePath();
      ctx.fill();
    },

    draw: function() {
      if (!this.context)
        throw new Vex.RERR("NoContext", "No context to render tie.");
      var first_note = this.from;
      var last_note = this.to;
      var first_x, last_x, first_y, last_y, stem_direction;

      var metric = "baseY";
      var end_metric = "baseY";
      var position = this.render_options.position;
      var position_end = this.render_options.position_end;

      if (position === Curve.Position.NEAR_TOP) {
        metric = "topY";
        end_metric = "topY";
      }

      if (position_end == Curve.Position.NEAR_HEAD) {
        end_metric = "baseY";
      } else if (position_end == Curve.Position.NEAR_TOP) {
        end_metric = "topY";
      }

      if (first_note) {
        first_x = first_note.getTieRightX();
        stem_direction = first_note.getStemDirection();
        first_y = first_note.getStemExtents()[metric];
      } else {
        first_x = last_note.getStave().getTieStartX();
        first_y = last_note.getStemExtents()[metric];
      }

      if (last_note) {
        last_x = last_note.getTieLeftX();
        stem_direction = last_note.getStemDirection();
        last_y = last_note.getStemExtents()[end_metric];
      } else {
        last_x = first_note.getStave().getTieEndX();
        last_y = first_note.getStemExtents()[end_metric];
      }

      this.renderCurve({
        first_x: first_x,
        last_x: last_x,
        first_y: first_y,
        last_y: last_y,
        direction: stem_direction *
          (this.render_options.invert === true ? -1 : 1)
      });
      return true;
    }
  };

  return Curve;
}());
// [VexFlow](http://vexflow.com) - Copyright (c) Mohit Muthanna 2010.
//
// ## Description
//
// This file implements `StaveLine` which are simply lines that connect
// two notes. This object is highly configurable, see the `render_options`.
// A simple line is often used for notating glissando articulations, but you
// can format a `StaveLine` with arrows or colors for more pedagogical
// purposes, such as diagrams.
Vex.Flow.StaveLine = (function() {
  function StaveLine(notes) {
    if (arguments.length > 0) this.init(notes);
  }

  // Text Positioning
  StaveLine.TextVerticalPosition = {
    TOP: 1,
    BOTTOM: 2
  };

  StaveLine.TextJustification = {
    LEFT: 1,
    CENTER: 2,
    RIGHT: 3
  };

  // ## Prototype Methods
  StaveLine.prototype = {
    // Initialize the StaveLine with the given `notes`.
    //
    // `notes` is a struct that has:
    //
    //  ```
    //  {
    //    first_note: Note,
    //    last_note: Note,
    //    first_indices: [n1, n2, n3],
    //    last_indices: [n1, n2, n3]
    //  }
    //  ```
    init: function(notes) {
      this.notes = notes;
      this.context = null;

      this.text = "";

      this.font = {
        family: "Arial",
        size: 10,
        weight: ""
      };

      this.render_options = {
        // Space to add to the left or the right
        padding_left: 4,
        padding_right: 3,

        // The width of the line in pixels
        line_width: 1,
        // An array of line/space lengths
        line_dash: null,
        // Can draw rounded line end, instead of a square
        rounded_end: true,
        // The color of the line and arrowheads
        color: null,

        // Flags to draw arrows on each end of the line
        draw_start_arrow: false,
        draw_end_arrow: false,

        // The length of the arrowhead sides
        arrowhead_length: 10,
        // The angle of the arrowhead
        arrowhead_angle: Math.PI / 8,

        // The position of the text
        text_position_vertical: StaveLine.TextVerticalPosition.TOP,
        text_justification: StaveLine.TextJustification.CENTER
      };

      this.setNotes(notes);
    },

    // Set the rendering context
    setContext: function(context) { this.context = context; return this; },
    // Set the font for the `StaveLine` text
    setFont: function(font) { this.font = font; return this; },
    // The the annotation for the `StaveLine`
    setText: function(text) { this.text = text; return this; },

    // Set the notes for the `StaveLine`
    setNotes: function(notes) {
      if (!notes.first_note && !notes.last_note)
        throw new Vex.RuntimeError("BadArguments",
            "Notes needs to have either first_note or last_note set.");

      if (!notes.first_indices) notes.first_indices = [0];
      if (!notes.last_indices) notes.last_indices = [0];

      if (notes.first_indices.length != notes.last_indices.length)
        throw new Vex.RuntimeError("BadArguments", "Connected notes must have similar" +
          " index sizes");

      // Success. Lets grab 'em notes.
      this.first_note = notes.first_note;
      this.first_indices = notes.first_indices;
      this.last_note = notes.last_note;
      this.last_indices = notes.last_indices;
      return this;
    },

    // Apply the style of the `StaveLine` to the context
    applyLineStyle: function() {
      if (!this.context) {
        throw new Vex.RERR("NoContext","No context to apply the styling to");
      }

      var render_options = this.render_options;
      var ctx = this.context;

      if (render_options.line_dash) {
        ctx.setLineDash(render_options.line_dash);
      }

      if (render_options.line_width) {
        ctx.setLineWidth(render_options.line_width);
      }

      if (render_options.rounded_end) {
        ctx.lineCap = "round";
      } else {
        ctx.lineCap = "square";
      }

      if (this.font) {
        ctx.setFont(this.font.family, this.font.size, this.font.weight);
      }
    },

    // Renders the `StaveLine` on the context
    draw: function() {
      if (!this.context) {
        throw new Vex.RERR("NoContext", "No context to render StaveLine.");
      }

      var ctx = this.context;
      var first_note = this.first_note;
      var last_note = this.last_note;
      var render_options = this.render_options;

      ctx.save();
      this.applyLineStyle();

      // Cycle through each set of indices and draw lines
      var start_position;
      var end_position;
      this.first_indices.forEach(function(first_index, i) {
        var last_index = this.last_indices[i];

        // Get initial coordinates for the start/end of the line
        start_position = first_note.getModifierStartXY(2, first_index);
        end_position = last_note.getModifierStartXY(1, last_index);
        var upwards_slope = start_position.y > end_position.y;

        // Adjust `x` coordinates for modifiers
        start_position.x += first_note.getMetrics().modRightPx +
                            render_options.padding_left;
        end_position.x -= last_note.getMetrics().modLeftPx +
                          render_options.padding_right;


        // Adjust first `x` coordinates for displacements
        var notehead_width = first_note.getGlyph().head_width;
        var first_displaced = first_note.getKeyProps()[first_index].displaced;
        if (first_displaced && first_note.getStemDirection() === 1) {
          start_position.x += notehead_width + render_options.padding_left;
        }

        // Adjust last `x` coordinates for displacements
        var last_displaced = last_note.getKeyProps()[last_index].displaced;
        if (last_displaced && last_note.getStemDirection() === -1) {
          end_position.x -= notehead_width + render_options.padding_right;
        }

        // Adjust y position better if it's not coming from the center of the note
        start_position.y += upwards_slope ? -3 : 1;
        end_position.y += upwards_slope ? 2 : 0;

        drawArrowLine(ctx, start_position, end_position, this.render_options);

      }, this);

      // Determine the x coordinate where to start the ext
      var text_width = ctx.measureText(this.text).width;
      var justification = render_options.text_justification;
      var x = 0;
      if (justification === StaveLine.TextJustification.LEFT) {
        x = start_position.x;
      } else if (justification === StaveLine.TextJustification.CENTER) {
        var delta_x = (end_position.x - start_position.x);
        var center_x = (delta_x / 2 ) + start_position.x;
        x = center_x - (text_width / 2);
      } else if (justification === StaveLine.TextJustification.RIGHT) {
        x = end_position.x  -  text_width;
      }

      // Determine the y value to start the text
      var y;
      var vertical_position = render_options.text_position_vertical;
      if (vertical_position === StaveLine.TextVerticalPosition.TOP) {
        y = first_note.getStave().getYForTopText();
      } else if (vertical_position === StaveLine.TextVerticalPosition.BOTTOM) {
        y = first_note.getStave().getYForBottomText();
      }

      // Draw the text
      ctx.fillText(this.text, x, y);
      ctx.restore();

      return this;
    }
  };

  // ## Private Helpers
  // 
  // Attribution: Arrow rendering implementations based off of
  // Patrick Horgan's article, "Drawing lines and arcs with 
  // arrow heads on  HTML5 Canvas"
  // 
  // Draw an arrow head that connects between 3 coordinates
  function drawArrowHead(ctx, x0, y0, x1, y1, x2, y2) {
    // all cases do this.
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x0,y0);
    ctx.lineTo(x1,y1);
    ctx.lineTo(x2,y2);

    // Close off the arrow lines with an arcTo curve
    var backdist = Math.sqrt(((x2-x0)*(x2-x0))+((y2-y0)*(y2-y0)));
    ctx.arcTo(x1, y1, x0, y0, 0.55 * backdist);

    ctx.fill();
    ctx.restore();
  }

  // Helper function to draw a line with arrow heads
  function drawArrowLine(ctx, point1, point2, config) {
    var both_arrows = config.draw_start_arrow && config.draw_end_arrow;

    var x1 = point1.x;
    var y1 = point1.y;
    var x2 = point2.x;
    var y2 = point2.y;

    // For ends with arrow we actually want to stop before we get to the arrow
    // so that wide lines won't put a flat end on the arrow.
    var distance = Math.sqrt((x2-x1)*(x2-x1)+(y2-y1)*(y2-y1));
    var ratio = (distance - config.arrowhead_length/3) / distance;
    var end_x, end_y, start_x, start_y;
    if (config.draw_end_arrow || both_arrows) {
      end_x = Math.round(x1 + (x2 - x1) * ratio);
      end_y = Math.round(y1 + (y2 - y1) * ratio);
    } else {
      end_x = x2;
      end_y = y2;
    }

    if (config.draw_start_arrow || both_arrows) {
      start_x = x1 + (x2 - x1) * (1 - ratio);
      start_y = y1 + (y2 - y1) * (1 - ratio);
    } else {
      start_x = x1;
      start_y = y1;
    }

    // Draw the shaft of the arrow
    ctx.beginPath();
    ctx.setStrokeStyle(config.color);
    ctx.setFillStyle(config.color);
    ctx.moveTo(start_x, start_y);
    ctx.lineTo(end_x,end_y);
    ctx.stroke();

    // calculate the angle of the line
    var line_angle = Math.atan2(y2 - y1, x2 - x1);
    // h is the line length of a side of the arrow head
    var h = Math.abs(config.arrowhead_length / Math.cos(config.arrowhead_angle));

    var angle1, angle2;
    var top_x, top_y;
    var bottom_x, bottom_y;

    if (config.draw_end_arrow || both_arrows) {
      angle1 = line_angle + Math.PI + config.arrowhead_angle;
      top_x = x2 + Math.cos(angle1) * h;
      top_y = y2 + Math.sin(angle1) * h;

      angle2 = line_angle + Math.PI - config.arrowhead_angle;
      bottom_x = x2 + Math.cos(angle2) * h;
      bottom_y = y2 + Math.sin(angle2) * h;

      drawArrowHead(ctx, top_x, top_y, x2, y2, bottom_x, bottom_y);
    }

    if (config.draw_start_arrow || both_arrows) {
      angle1 = line_angle + config.arrowhead_angle;
      top_x = x1 + Math.cos(angle1) * h;
      top_y = y1 + Math.sin(angle1) * h;

      angle2 = line_angle - config.arrowhead_angle;
      bottom_x = x1 + Math.cos(angle2) * h;
      bottom_y = y1 + Math.sin(angle2) * h;

      drawArrowHead(ctx, top_x, top_y, x1, y1, bottom_x, bottom_y);
    }
  }

  return StaveLine;
}());
Vex.Flow.GraceNote = (function() {
  var GraceNote = function(note_struct) {
    if (arguments.length > 0) this.init(note_struct);
  };

  Vex.Inherit(GraceNote, Vex.Flow.StaveNote, {
    init: function(note_struct) {
      GraceNote.superclass.init.call(this, note_struct);

      this.render_options.glyph_font_scale = 22;
      this.render_options.stem_height = 20;
      this.render_options.stroke_px = 2;
      this.glyph.head_width = 6;

      this.slash = note_struct.slash;
      this.slur = true;

      this.buildNoteHeads();

      this.width = 3;
    },

    getStemExtension: function(){
      var glyph = this.getGlyph();

      if (this.stem_extension_override != null) {
        return this.stem_extension_override;
      }

      if (glyph) {
        return this.getStemDirection() === 1 ? glyph.gracenote_stem_up_extension :
          glyph.gracenote_stem_down_extension;
      }

      return 0;
    },

    getCategory: function() { return 'gracenotes'; },

    draw: function(){
      GraceNote.superclass.draw.call(this);
      var ctx = this.context;
      var stem_direction = this.getStemDirection();

      if (this.slash) {
        ctx.beginPath();

        var x = this.getAbsoluteX();
        var y = this.getYs()[0] - (this.stem.getHeight() / 2.8);
        if (stem_direction === 1) {
          x += 1;
          ctx.lineTo(x, y);
          ctx.lineTo(x + 13, y - 9);
        } else if (stem_direction === -1) {
          x -= 4;
          y += 1;
          ctx.lineTo(x, y);
          ctx.lineTo(x + 13, y + 9);
        }

        ctx.closePath();
        ctx.stroke();
      }
    }
  });

  return GraceNote;
}());
Vex.Flow.GraceNoteGroup = (function(){
  var GraceNoteGroup = function(grace_notes, config) {
    if (arguments.length > 0) this.init(grace_notes, config);
  };

  Vex.Inherit(GraceNoteGroup, Vex.Flow.Modifier, {
    init: function(grace_notes, show_slur) {
      var superclass = GraceNoteGroup.superclass;
      superclass.init.call(this);

      this.note = null;
      this.index = null;
      this.position = Vex.Flow.Modifier.Position.LEFT;
      this.grace_notes = grace_notes;
      this.width = 0;

      this.preFormatted = false;

      this.show_slur = show_slur;
      this.slur = null;

      this.formatter = new Vex.Flow.Formatter();
      this.voice = new Vex.Flow.Voice({
        num_beats: 4,
        beat_value: 4,
        resolution: Vex.Flow.RESOLUTION
      }).setStrict(false);

      this.voice.addTickables(this.grace_notes);

      return this;
    },

    preFormat: function(){
      if (this.preFormatted) return;

      this.formatter.joinVoices([this.voice]).format([this.voice], 0);
      this.setWidth(this.formatter.getMinTotalWidth());

      this.preFormatted = true;
    },

    beamNotes: function(){
      if (this.grace_notes.length > 1) {
        var beam = new Vex.Flow.Beam(this.grace_notes);

        beam.render_options.beam_width = 3;
        beam.render_options.partial_beam_length = 4;

        this.beam = beam;
      }

      return this;
    },

    setNote: function(note) {
      this.note = note;
    },
    getCategory: function() { return "gracenotegroups"; },
    setWidth: function(width){
      this.width = width;
    },
    getWidth: function(){
      return this.width;
    },
    setXShift: function(x_shift) {
        this.x_shift = x_shift;
    },
    draw: function() {
      if (!this.context)  {
        throw new Vex.RuntimeError("NoContext",
          "Can't draw Grace note without a context.");
      }

      var note = this.getNote();

      if (!(note && (this.index !== null))) {
        throw new Vex.RuntimeError("NoAttachedNote",
          "Can't draw grace note without a parent note and parent note index.");
      }

      function alignGraceNotesWithNote(grace_notes, note) {
        // Shift over the tick contexts of each note
        // So that th aligned with the note
        var tickContext = note.getTickContext();
        var extraPx = tickContext.getExtraPx();
        var x = tickContext.getX() - extraPx.left - extraPx.extraLeft;
        grace_notes.forEach(function(graceNote) {
            var tick_context = graceNote.getTickContext();
            var x_offset = tick_context.getX();
            graceNote.setStave(note.stave);
            tick_context.setX(x + x_offset);
        });
      }

      alignGraceNotesWithNote(this.grace_notes, note);

      // Draw notes
      this.grace_notes.forEach(function(graceNote) {
        graceNote.setContext(this.context).draw();
      }, this);

      // Draw beam
      if (this.beam) {
        this.beam.setContext(this.context).draw();
      }

      if (this.show_slur) {
        // Create and draw slur
        this.slur = new Vex.Flow.StaveTie({
          last_note: this.grace_notes[0],
          first_note: note,
          first_indices: [0],
          last_indices: [0]
        });

        this.slur.render_options.cp2 = 12;
        this.slur.setContext(this.context).draw();
      }
    }
  });

return GraceNoteGroup;
}());