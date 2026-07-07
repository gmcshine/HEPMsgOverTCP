package main

import (
	"bufio"
	"context"
	"fmt"
	"image/color"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type processRunner struct {
	mu            sync.Mutex
	cmd           *exec.Cmd
	cancel        context.CancelFunc
	stopRequested bool
}

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func (r *processRunner) isRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cmd != nil
}

func (r *processRunner) start(command string, args []string, onLine func(string), onExit func(error)) error {
	r.mu.Lock()
	if r.cmd != nil {
		r.mu.Unlock()
		return fmt.Errorf("process is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, command, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		r.mu.Unlock()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		r.mu.Unlock()
		return err
	}
	if err = cmd.Start(); err != nil {
		cancel()
		r.mu.Unlock()
		return err
	}
	r.cmd = cmd
	r.cancel = cancel
	r.stopRequested = false
	r.mu.Unlock()

	go streamOutput(stdout, onLine)
	go streamOutput(stderr, onLine)
	go func() {
		errWait := cmd.Wait()
		r.mu.Lock()
		r.cmd = nil
		r.cancel = nil
		r.mu.Unlock()
		onExit(errWait)
	}()
	return nil
}

func (r *processRunner) stop() {
	r.mu.Lock()
	cmd := r.cmd
	cancel := r.cancel
	r.stopRequested = true
	r.mu.Unlock()

	if cmd != nil && cmd.Process != nil && strings.EqualFold(os.Getenv("OS"), "Windows_NT") {
		_ = exec.Command("taskkill", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
	}
	if cancel != nil {
		cancel()
	}
}

func (r *processRunner) wasStopRequested() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopRequested
}

func streamOutput(reader io.Reader, onLine func(string)) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		onLine(scanner.Text())
	}
}

func appendLog(logBox *widget.Entry, line string) {
	timePrefix := time.Now().Format("15:04:05")
	cleanLine := ansiEscapePattern.ReplaceAllString(line, "")
	logBox.SetText(logBox.Text + "[" + timePrefix + "] " + cleanLine + "\n")
}

func parsePositiveInt(fieldName string, text string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", fieldName)
	}
	return value, nil
}

func main() {
	if strings.EqualFold(os.Getenv("OS"), "Windows_NT") && strings.TrimSpace(os.Getenv("FYNE_SCALE")) == "" {
		_ = os.Setenv("FYNE_SCALE", "1")
	}

	a := app.New()
	w := a.NewWindow("HEP Receiver")
	w.Resize(fyne.NewSize(680, 560))

	receiverRunner := &processRunner{}
	statusLabel := widget.NewLabel("Ready")
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	stateBg := canvas.NewRectangle(color.NRGBA{R: 99, G: 102, B: 106, A: 255})
	stateBg.SetMinSize(fyne.NewSize(220, 42))
	stateTitle := canvas.NewText("Receiver", color.White)
	stateTitle.TextStyle = fyne.TextStyle{Bold: true}
	stateText := canvas.NewText("Idle", color.White)
	stateText.TextStyle = fyne.TextStyle{Bold: true}
	stateCard := container.NewMax(
		stateBg,
		container.NewPadded(container.NewHBox(stateTitle, canvas.NewText(": ", color.White), stateText)),
	)
	updateState := func(state string, bgColor color.Color) {
		stateBg.FillColor = bgColor
		stateBg.Refresh()
		stateText.Text = state
		stateText.Refresh()
	}

	logBox := widget.NewMultiLineEntry()
	logBox.SetMinRowsVisible(16)
	logBox.Wrapping = fyne.TextWrapWord

	receiverTLS := widget.NewCheck("Enable TLS (-tls)", nil)
	receiverDetail := widget.NewCheck("Detail log (-dl)", nil)
	receiverDecodeCount := widget.NewCheck("Decode and count (-dc)", nil)
	receiverChecks := container.NewHBox(receiverTLS, receiverDetail, receiverDecodeCount)

	receiverProtocol := widget.NewSelect([]string{"tcp", "udp"}, nil)
	receiverProtocol.SetSelected("tcp")
	receiverIP := widget.NewEntry()
	receiverIP.SetPlaceHolder("empty means all interfaces")
	receiverPort := widget.NewEntry()
	receiverPort.SetText("9889")

	startReceiver := widget.NewButtonWithIcon("Start Receiver", theme.MediaPlayIcon(), func() {
		if receiverRunner.isRunning() {
			statusLabel.SetText("Receiver is already running")
			updateState("Already running", color.NRGBA{R: 183, G: 109, B: 0, A: 255})
			return
		}
		lp, err := parsePositiveInt("listening port", receiverPort.Text)
		if err != nil {
			statusLabel.SetText(err.Error())
			return
		}
		args := []string{
			"run", "hepReceiver.go",
			"-tu", strings.TrimSpace(receiverProtocol.Selected),
			"-la", strings.TrimSpace(receiverIP.Text),
			"-lp", strconv.Itoa(lp),
		}
		if receiverTLS.Checked {
			args = append(args, "-tls")
		}
		if receiverDetail.Checked {
			args = append(args, "-dl")
		}
		if receiverDecodeCount.Checked {
			args = append(args, "-dc")
		}

		statusLabel.SetText("Starting receiver...")
		updateState("Starting", color.NRGBA{R: 183, G: 109, B: 0, A: 255})
		appendLog(logBox, "Start receiver: go "+strings.Join(args, " "))

		err = receiverRunner.start(
			"go",
			args,
			func(line string) { appendLog(logBox, "[receiver] "+line) },
			func(exitErr error) {
				if exitErr != nil && !receiverRunner.wasStopRequested() {
					statusLabel.SetText("Receiver exited with error")
					updateState("Error", color.NRGBA{R: 183, G: 28, B: 28, A: 255})
					appendLog(logBox, "[receiver] exited: "+exitErr.Error())
					return
				}
				statusLabel.SetText("Receiver stopped")
				updateState("Stopped", color.NRGBA{R: 99, G: 102, B: 106, A: 255})
				appendLog(logBox, "[receiver] exited normally")
			},
		)
		if err != nil {
			statusLabel.SetText("Failed to start receiver")
			updateState("Start failed", color.NRGBA{R: 183, G: 28, B: 28, A: 255})
			appendLog(logBox, "[receiver] start failed: "+err.Error())
			return
		}
		updateState("Running", color.NRGBA{R: 27, G: 94, B: 32, A: 255})
	})
	startReceiver.Importance = widget.HighImportance

	stopReceiver := widget.NewButtonWithIcon("Stop Receiver", theme.MediaStopIcon(), func() {
		if !receiverRunner.isRunning() {
			statusLabel.SetText("Receiver is not running")
			updateState("Not running", color.NRGBA{R: 99, G: 102, B: 106, A: 255})
			return
		}
		statusLabel.SetText("Stopping receiver...")
		updateState("Stopping", color.NRGBA{R: 183, G: 109, B: 0, A: 255})
		appendLog(logBox, "Stopping receiver...")
		receiverRunner.stop()
	})
	stopReceiver.Importance = widget.DangerImportance

	receiverForm := widget.NewForm(
		widget.NewFormItem("Protocol (-tu)", receiverProtocol),
		widget.NewFormItem("Listen IP (-la)", receiverIP),
		widget.NewFormItem("Listen Port (-lp)", receiverPort),
	)

	controls := container.NewVBox(
		widget.NewLabel("Receiver Parameters"),
		stateCard,
		receiverChecks,
		receiverForm,
		container.NewHBox(startReceiver, stopReceiver, layout.NewSpacer()),
	)
	logs := container.NewBorder(
		widget.NewLabel("Receiver Logs"),
		container.NewHBox(layout.NewSpacer(), widget.NewButton("Clear Receiver Logs", func() { logBox.SetText("") })),
		nil,
		nil,
		logBox,
	)

	w.SetContent(container.NewBorder(
		container.NewVBox(statusLabel),
		nil,
		nil,
		nil,
		container.NewBorder(controls, nil, nil, nil, logs),
	))
	w.SetCloseIntercept(func() {
		receiverRunner.stop()
		w.Close()
	})
	w.ShowAndRun()
}