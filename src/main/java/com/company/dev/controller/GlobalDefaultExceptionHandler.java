package com.company.dev.controller;

import com.company.dev.util.ForbiddenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

@ControllerAdvice
class GlobalDefaultExceptionHandler {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public static final String DEFAULT_ERROR_VIEW = "error";

    @ExceptionHandler(value = Exception.class)
    public ModelAndView
    defaultErrorHandler(HttpServletRequest req, Exception e) throws Exception {
        logger.error("entered defualtErrorHandler");
        // If the exception is annotated with @ResponseStatus rethrow it and let
        // the framework handle it.
        // AnnotationUtils is a Spring Framework utility class.
        if (AnnotationUtils.findAnnotation(e.getClass(), ResponseStatus.class) != null) {
            logger.error(e.getMessage());
            throw e;
        }

        // Otherwise setup and send the user to a default error-view.
        ModelAndView mav = new ModelAndView();
        mav.addObject("exception", e);
        mav.addObject("url", req.getRequestURL());
        mav.setViewName(DEFAULT_ERROR_VIEW);
        logger.error("did we get here?");
        return mav;
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Bad Request")
    @ExceptionHandler(InvalidCsrfTokenException.class)
    public void handleConflictCsrf() {
        // Nothing to do
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Bad Request")
    @ExceptionHandler(IllegalStateException.class)
    public void handleConflict() {
        // Nothing to do
    }
}