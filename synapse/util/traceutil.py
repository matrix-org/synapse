# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time

import inspect
import logging


logger = logging.getLogger("Tracer")


class Tracer(object):

    def __init__(self):
        self.interested_deferreds = set()

        self.next_id = 1

        self.deferred_frames = {}
        self.deferred_to_current_frames = {}

    def process(self, frame, event, arg):
        if event == 'call':
            return self.process_call(frame)

    def handle_inline_callbacks(self, frm):
        argvalues = inspect.getargvalues(frm)
        generator = argvalues.locals["g"]
        deferred = argvalues.locals["deferred"]

        if not hasattr(deferred, "syn_trace_defer_id"):
            trace_id = self.get_next_id()
            deferred.syn_trace_defer_id = trace_id
            logger.info(
                "%s named %s",
                trace_id,
                self.get_name_for_frame(generator.gi_frame)
            )

            logger.info(
                "%s is deferred",
                trace_id,
            )

            logger.info("%s start %d", trace_id, int(time.time() * 1000))

            def do(res):
                logger.info("%s end %d", trace_id, int(time.time() * 1000))
                return res

            deferred.addBoth(do)

            back = frm.f_back
            while back:
                try:
                    name = self.get_name_for_frame(back)
                    if name == "twisted.internet.defer._inlineCallbacks":
                        argvalues = inspect.getargvalues(back)
                        deferred = argvalues.locals["deferred"]

                        d_id = getattr(deferred, "syn_trace_defer_id", None)
                        if d_id:
                            logger.info("%s in %s", trace_id, d_id)
                            curr_stack = self.deferred_to_current_frames.setdefault(
                                d_id, []
                            )

                            if curr_stack:
                                logger.info("%s calls %s", curr_stack[-1], trace_id)
                            else:
                                logger.info("%s calls %s", d_id, trace_id)
                            break

                except:
                    pass

                back = back.f_back

    def are_interested(self, name):
        if not name.startswith("synapse"):
            return False
        if name.startswith("synapse.util.logcontext"):
            return False
        if name.startswith("synapse.util.logutils"):
            return False
        if name.startswith("synapse.util.traceutil"):
            return False
        if name.startswith("synapse.events.FrozenEvent.get"):
            return False
        if name.startswith("synapse.events.EventBuilder.get"):
            return False
        if name.startswith("synapse.types"):
            return False
        if name.startswith("synapse.util.frozenutils.freeze"):
            return False
        if name.startswith("synapse.util.frozenutils.<dictcomp>"):
            return False
        if name.startswith("synapse.util.Clock"):
            return False

        if name.endswith("__repr__") or name.endswith("__str__"):
            return False
        if name.endswith("<genexpr>"):
            return False

        return True

    def process_call(self, frame):
        should_trace = False

        try:
            name = self.get_name_for_frame(frame)
            if name == "twisted.internet.defer._inlineCallbacks":
                self.handle_inline_callbacks(frame)
                return

            if not self.are_interested(name):
                return

            back_name = self.get_name_for_frame(frame.f_back)

            if name == "synapse.api.auth.Auth.get_user_by_req":
                logger.info(
                    "synapse.api.auth.Auth.get_user_by_req %s",
                    back_name
                )

            try:
                if back_name == "twisted.internet.defer._inlineCallbacks":
                    def ret(f, event, result):
                        if event != "return":
                            return

                        argvalues = inspect.getargvalues(frame.f_back)
                        deferred = argvalues.locals["deferred"]

                        try:
                            logger.info(
                                "%s waits on %s",
                                deferred.syn_trace_defer_id,
                                result.syn_trace_defer_id
                            )
                        except:
                            pass
                    return ret
                if back_name == "twisted.internet.defer.unwindGenerator":
                    return
            except:
                pass

            try:
                func = getattr(frame.f_locals["self"], frame.f_code.co_name)
                if inspect.isgeneratorfunction(func):
                    return
            except:
                pass

            try:
                func = frame.f_globals[frame.f_code.co_name]
                if inspect.isgeneratorfunction(func):
                    return
            except:
                pass
        except:
            return

        back = frame
        names = []

        seen_deferreds = []
        bottom_deferred = None
        while back:
            try:
                name = self.get_name_for_frame(back)
                if name.startswith("synapse"):
                    names.append(name)

                # if name.startswith("twisted.internet.defer"):
                #     logger.info("Name: %s", name)

                if name == "twisted.internet.defer._inlineCallbacks":
                    argvalues = inspect.getargvalues(back)
                    deferred = argvalues.locals["deferred"]

                    d_id = getattr(deferred, "syn_trace_defer_id", None)
                    if d_id:
                        seen_deferreds.append(d_id)
                        if not bottom_deferred:
                            bottom_deferred = deferred
                    if d_id in self.interested_deferreds:
                        should_trace = True
                        break

                func = getattr(back.f_locals["self"], back.f_code.co_name)

                if hasattr(func, "should_trace") or hasattr(func.im_func, "should_trace"):
                    should_trace = True
                    break

                func.root_trace
                should_trace = True

                break
            except:
                pass

            back = back.f_back

        if not should_trace:
            return

        frame_id = self.get_next_id()
        name = self.get_name_for_frame(frame)
        logger.info("%s named %s", frame_id, name)

        self.interested_deferreds.update(seen_deferreds)

        names.reverse()

        if bottom_deferred:
            self.deferred_frames.setdefault(
                bottom_deferred.syn_trace_defer_id, []
            ).append(names)

            logger.info("%s in %s", frame_id, bottom_deferred.syn_trace_defer_id)

            if not hasattr(bottom_deferred, "syn_trace_registered_cb"):
                bottom_deferred.syn_trace_registered_cb = True

                def do(res):
                    return res

                bottom_deferred.addBoth(do)

            curr_stack = self.deferred_to_current_frames.setdefault(
                bottom_deferred.syn_trace_defer_id, []
            )

            if curr_stack:
                logger.info("%s calls %s", curr_stack[-1], frame_id)
            else:
                logger.info("%s calls %s", bottom_deferred.syn_trace_defer_id, frame_id)

            curr_stack.append(frame_id)

            logger.info("%s start %d", frame_id, int(time.time() * 1000))

            def p(frame, event, arg):
                if event == "return":
                    curr_stack.pop()

                    logger.info("%s end %d", frame_id, int(time.time() * 1000))

            return p

    def get_name_for_frame(self, frame):
        module_name = frame.f_globals["__name__"]
        cls_instance = frame.f_locals.get("self", None)
        if cls_instance:
            cls_name = cls_instance.__class__.__name__
            name = "%s.%s.%s" % (
                module_name, cls_name, frame.f_code.co_name
            )
        else:
            name = "%s.%s" % (
                module_name, frame.f_code.co_name
            )
        return name

    def get_next_id(self):
        i = self.next_id
        self.next_id += 1
        return i
