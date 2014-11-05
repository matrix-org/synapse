describe('durationFilter', function() {
    var filter, durationFilter;
    
    beforeEach(module('matrixWebClient'));
    beforeEach(module('matrixFilter'));
    beforeEach(inject(function($filter) {
        filter = $filter;
        durationFilter = filter("duration");
    }));
    
    it("should represent 15000 ms as '15s'", function() {
        var output = durationFilter(15000);
        expect(output).toEqual("15s");
    });
    
    it("should represent 60000 ms as '1m'", function() {
        var output = durationFilter(60000);
        expect(output).toEqual("1m");
    });
    
    it("should represent 65000 ms as '1m'", function() {
        var output = durationFilter(65000);
        expect(output).toEqual("1m");
    });
    
    it("should represent 10 ms as '0s'", function() {
        var output = durationFilter(10);
        expect(output).toEqual("0s");
    });
    
    it("should represent 4m as '4m'", function() {
        var output = durationFilter(1000*60*4);
        expect(output).toEqual("4m");
    });
    
    it("should represent 4m30s as '4m'", function() {
        var output = durationFilter(1000*60*4 + 1000*30);
        expect(output).toEqual("4m");
    });
    
    it("should represent 2h as '2h'", function() {
        var output = durationFilter(1000*60*60*2);
        expect(output).toEqual("2h");
    });
    
    it("should represent 2h35m as '2h'", function() {
        var output = durationFilter(1000*60*60*2 + 1000*60*35);
        expect(output).toEqual("2h");
    });
});